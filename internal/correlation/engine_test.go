package correlation

import (
	"context"
	"regexp"
	"sync"
	"testing"
	"time"

	"muvon/internal/config"
	"muvon/internal/logger"
)

// fakeSink records every alert; tests read .alerts under the mutex.
type fakeSink struct {
	mu     sync.Mutex
	alerts []Alert
}

func (f *fakeSink) HandleAlert(_ context.Context, a Alert) {
	f.mu.Lock()
	f.alerts = append(f.alerts, a)
	f.mu.Unlock()
}

func (f *fakeSink) byRule(rule string) []Alert {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Alert
	for _, a := range f.alerts {
		if a.Rule == rule {
			out = append(out, a)
		}
	}
	return out
}

func defaultTestConfig() config.CorrelationConfig {
	return config.CorrelationConfig{
		PathScanDistinct: 10,
		PathScanWindow:   2 * time.Minute,

		AuthBruteCount:  5,
		AuthBruteWindow: 2 * time.Minute,
		AuthPaths: []string{
			"/login",
			"/api/auth/login",
			"/api/authentication/login/",
		},

		WafRepeatCount:  3,
		WafRepeatWindow: 5 * time.Minute,

		ErrorSpikeCount:  10,
		ErrorSpikeWindow: time.Minute,

		AnomalyEnabled:     true,
		AnomalyRatio:       3.0,
		AnomalyBaseline:    10 * time.Minute,
		AnomalyCurrent:     time.Minute,
		AnomalyMinBaseline: 20,

		SensitivePaths:     []string{"/api/export/*"},
		SensitiveThreshold: 5,
		SensitiveWindow:    5 * time.Minute,

		ExportPattern:   regexp.MustCompile(`(?i)(download|export|\.pdf)`),
		ExportThreshold: 5,
		ExportWindow:    5 * time.Minute,
	}
}

func newEngine(cfg config.CorrelationConfig) (*Engine, *fakeSink) {
	sink := &fakeSink{}
	return New(sink, func() config.CorrelationConfig { return cfg }), sink
}

// Helper that feeds an entry into the engine without starting the subscription goroutine.
func (e *Engine) fire(entry logger.Entry) {
	e.process(entry)
}

func entry(ip, path string, status int) logger.Entry {
	return logger.Entry{
		Timestamp:      time.Now(),
		Host:           "app.example.com",
		ClientIP:       ip,
		Method:         "GET",
		Path:           path,
		ResponseStatus: status,
	}
}

// --- Rule 1: path_scan -------------------------------------------------------

func TestPathScanFires(t *testing.T) {
	eng, sink := newEngine(defaultTestConfig())
	for i := 0; i < 10; i++ {
		eng.fire(entry("1.2.3.4", "/missing/"+string(rune('a'+i)), 404))
	}
	if len(sink.byRule("path_scan")) != 1 {
		t.Fatalf("expected 1 path_scan alert, got %d", len(sink.byRule("path_scan")))
	}
}

func TestPathScanIgnoresSamePathRepeats(t *testing.T) {
	eng, sink := newEngine(defaultTestConfig())
	for i := 0; i < 20; i++ {
		eng.fire(entry("1.2.3.4", "/same-path", 404))
	}
	if len(sink.byRule("path_scan")) != 0 {
		t.Fatal("same path repeated should not count as scan")
	}
}

// --- Rule 2: auth_brute_force -----------------------------------------------

func TestAuthBruteForceFiresOn401(t *testing.T) {
	eng, sink := newEngine(defaultTestConfig())
	for i := 0; i < 5; i++ {
		eng.fire(entry("10.0.0.1", "/api/token/", 401))
	}
	if len(sink.byRule("auth_brute_force")) != 1 {
		t.Fatalf("expected 1 auth_brute_force, got %d", len(sink.byRule("auth_brute_force")))
	}
}

// This is the Django simplejwt case — bad password returns 400, not 401.
// Without the path-aware rule this test would not fire.
func TestAuthBruteForceFiresOn400AtLoginPath(t *testing.T) {
	eng, sink := newEngine(defaultTestConfig())
	for i := 0; i < 5; i++ {
		eng.fire(entry("10.0.0.2", "/api/auth/login", 400))
	}
	if len(sink.byRule("auth_brute_force")) != 1 {
		t.Fatalf("expected brute force to fire on 400 at login path, got %d", len(sink.byRule("auth_brute_force")))
	}
}

func TestAuthBruteForceIgnores400OffLoginPath(t *testing.T) {
	eng, sink := newEngine(defaultTestConfig())
	for i := 0; i < 5; i++ {
		eng.fire(entry("10.0.0.3", "/api/orders/", 400))
	}
	if len(sink.byRule("auth_brute_force")) != 0 {
		t.Fatal("400 outside auth paths must not count as auth failure")
	}
}

func TestAuthBruteForceTrailingSlashInsensitive(t *testing.T) {
	eng, sink := newEngine(defaultTestConfig())
	// Config has /api/authentication/login/; request hits /api/authentication/login (no slash).
	for i := 0; i < 5; i++ {
		eng.fire(entry("10.0.0.4", "/api/authentication/login", 400))
	}
	if len(sink.byRule("auth_brute_force")) != 1 {
		t.Fatal("trailing slash difference should not prevent match")
	}
}

// --- Rule 3: error_spike -----------------------------------------------------

func TestErrorSpikeFires(t *testing.T) {
	eng, sink := newEngine(defaultTestConfig())
	for i := 0; i < 10; i++ {
		eng.fire(entry("1.1.1.1", "/api/broken", 500))
	}
	if len(sink.byRule("error_spike")) != 1 {
		t.Fatalf("expected error_spike to fire once, got %d", len(sink.byRule("error_spike")))
	}
}

func TestErrorSpikeDoesNotFireUnderThreshold(t *testing.T) {
	eng, sink := newEngine(defaultTestConfig())
	for i := 0; i < 9; i++ {
		eng.fire(entry("1.1.1.1", "/api/broken", 500))
	}
	if len(sink.byRule("error_spike")) != 0 {
		t.Fatal("9 errors should not fire the 10-event threshold rule")
	}
}

// --- Rule 4: waf_repeat_offender --------------------------------------------

func TestWafRepeatOffenderFires(t *testing.T) {
	eng, sink := newEngine(defaultTestConfig())
	for i := 0; i < 3; i++ {
		e := entry("5.5.5.5", "/anywhere", 403)
		e.WafBlocked = true
		eng.fire(e)
	}
	if len(sink.byRule("waf_repeat_offender")) != 1 {
		t.Fatalf("expected waf_repeat_offender, got %d", len(sink.byRule("waf_repeat_offender")))
	}
}

// --- Rule 5: traffic_anomaly ------------------------------------------------

func TestTrafficAnomalyFiresOnSpike(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.AnomalyBaseline = 60 * time.Second
	cfg.AnomalyCurrent = 10 * time.Second
	cfg.AnomalyMinBaseline = 20

	eng, sink := newEngine(cfg)
	now := time.Now()

	// Pre-seed the host window directly — normal Send() flow would throttle
	// us to one anomaly check per 5s, which makes it impossible to push
	// enough events through in a tight test loop. By setting the state and
	// then firing a single event we exercise exactly the anomaly branch we
	// care about.
	events := make([]time.Time, 0, 60)
	// Baseline: 30 events spread over (−60s, −11s).
	for i := 0; i < 30; i++ {
		events = append(events, now.Add(time.Duration(-60+i)*time.Second))
	}
	// Spike: 25 events in the current 10s window.
	for i := 0; i < 25; i++ {
		events = append(events, now.Add(-time.Duration(10-i/3)*time.Second))
	}
	eng.mu.Lock()
	eng.hostCounts["app.example.com"] = &hostWindow{events: events}
	eng.mu.Unlock()

	eng.fire(logger.Entry{
		Timestamp:      now,
		Host:           "app.example.com",
		ClientIP:       "1.1.1.1",
		Path:           "/",
		ResponseStatus: 200,
	})

	if len(sink.byRule("traffic_anomaly")) == 0 {
		t.Fatal("expected traffic_anomaly to fire on pre-seeded spike")
	}
}

func TestTrafficAnomalyRequiresMinBaseline(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.AnomalyMinBaseline = 50 // higher than events in this test
	eng, sink := newEngine(cfg)

	for i := 0; i < 30; i++ {
		eng.fire(entry("1.1.1.1", "/", 200))
	}
	if len(sink.byRule("traffic_anomaly")) != 0 {
		t.Fatal("low-traffic hosts must not trip anomaly")
	}
}

// --- Rule 6: sensitive_access -----------------------------------------------

func TestSensitiveAccessFiresOnPattern(t *testing.T) {
	eng, sink := newEngine(defaultTestConfig())
	for i := 0; i < 5; i++ {
		eng.fire(entry("2.2.2.2", "/api/export/report", 200))
	}
	if len(sink.byRule("sensitive_access")) != 1 {
		t.Fatalf("expected sensitive_access, got %d", len(sink.byRule("sensitive_access")))
	}
}

func TestSensitiveAccessIgnoresUnmatchedPaths(t *testing.T) {
	eng, sink := newEngine(defaultTestConfig())
	for i := 0; i < 20; i++ {
		eng.fire(entry("2.2.2.2", "/api/orders/123", 200))
	}
	if len(sink.byRule("sensitive_access")) != 0 {
		t.Fatal("unrelated paths must not trigger sensitive_access")
	}
}

func TestSensitiveAccessDisabledWhenNoPaths(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.SensitivePaths = nil
	eng, sink := newEngine(cfg)
	for i := 0; i < 20; i++ {
		eng.fire(entry("2.2.2.2", "/api/export/report", 200))
	}
	if len(sink.byRule("sensitive_access")) != 0 {
		t.Fatal("empty SensitivePaths must disable the rule")
	}
}

// --- Rule 7: data_export_burst ----------------------------------------------

func TestExportBurstFiresPerUser(t *testing.T) {
	eng, sink := newEngine(defaultTestConfig())
	e := logger.Entry{
		Host:           "app.example.com",
		Method:         "GET",
		ResponseStatus: 200,
		UserIdentity: &logger.UserIdentity{
			Claims:   map[string]string{"sub": "user-42"},
			Verified: true,
			Source:   "jwt_verify",
		},
	}
	for i := 0; i < 5; i++ {
		e.Timestamp = time.Now()
		// Path must match the rule's ExportPattern (which looks for words
		// like "download", "export", or a file extension like .pdf).
		e.Path = "/api/applications/123/report.pdf"
		eng.fire(e)
	}
	alerts := sink.byRule("data_export_burst")
	if len(alerts) != 1 {
		t.Fatalf("expected 1 data_export_burst, got %d", len(alerts))
	}
	if alerts[0].Fingerprint != "data_export_burst:user:user-42" {
		t.Fatalf("fingerprint should be keyed by user claim, got %q", alerts[0].Fingerprint)
	}
}

func TestExportBurstFallsBackToIP(t *testing.T) {
	eng, sink := newEngine(defaultTestConfig())
	for i := 0; i < 5; i++ {
		eng.fire(entry("9.9.9.9", "/downloads/statement.pdf", 200))
	}
	alerts := sink.byRule("data_export_burst")
	if len(alerts) != 1 || alerts[0].Fingerprint != "data_export_burst:ip:9.9.9.9" {
		t.Fatalf("expected IP-keyed export burst alert, got %+v", alerts)
	}
}

func TestExportBurstDisabledWhenPatternNil(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.ExportPattern = nil
	eng, sink := newEngine(cfg)
	for i := 0; i < 10; i++ {
		eng.fire(entry("9.9.9.9", "/downloads/foo.pdf", 200))
	}
	if len(sink.byRule("data_export_burst")) != 0 {
		t.Fatal("nil pattern must disable export burst")
	}
}

// --- Helpers ---------------------------------------------------------------

func TestPathExactMatchTrailingSlash(t *testing.T) {
	patterns := []string{"/api/auth/login/", "/login"}
	if !pathExactMatch("/api/auth/login", patterns) {
		t.Fatal("pattern-with-slash should match request-without-slash")
	}
	if !pathExactMatch("/login/", patterns) {
		t.Fatal("request-with-slash should match pattern-without-slash")
	}
	if pathExactMatch("/api/other", patterns) {
		t.Fatal("unrelated path must not match")
	}
}

func TestPathGlobMatch(t *testing.T) {
	patterns := []string{"/api/applications/*/generate_pdf_report/"}
	if !pathGlobMatch("/api/applications/123/generate_pdf_report/", patterns) {
		t.Fatal("single-segment wildcard should match")
	}
	if pathGlobMatch("/api/applications/123/other/", patterns) {
		t.Fatal("unrelated segment must not match")
	}
}
