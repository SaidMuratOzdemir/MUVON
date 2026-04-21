package correlation

import (
	"context"
	"log/slog"
	"path"
	"sync"
	"time"

	"muvon/internal/config"
	"muvon/internal/logger"
)

// Alert represents a correlation alert to be persisted and optionally notified.
type Alert struct {
	Rule        string
	Severity    string // "info", "warning", "critical"
	Title       string
	Detail      map[string]any
	SourceIP    string
	Host        string
	Fingerprint string
}

// AlertSink receives alerts produced by the correlation engine.
type AlertSink interface {
	HandleAlert(ctx context.Context, alert Alert)
}

// ConfigFunc returns the latest correlation tunables. The engine calls this
// per-event so that admin-panel changes take effect on the next request
// without a restart.
type ConfigFunc func() config.CorrelationConfig

// Engine subscribes to the log pipeline and evaluates sliding-window rules.
type Engine struct {
	sink     AlertSink
	configFn ConfigFunc
	quit     chan struct{}
	stopped  chan struct{}

	mu          sync.Mutex
	ipCounts    map[string]*ipWindow
	hostCounts  map[string]*hostWindow
	actorCounts map[string]*actorWindow // keyed by "user:<id>" or "ip:<ip>"
}

// ipWindow holds per-IP sliding-window state shared across IP-scoped rules.
// Each list is pruned on every relevant event so memory stays proportional
// to recent activity, not lifetime volume.
type ipWindow struct {
	notFound             []time.Time
	authFail             []time.Time
	wafBlocks            []time.Time
	paths404             map[string]struct{}
	sensitive            []time.Time
	sensitiveSamplePaths []string
	lastActive           time.Time
}

// hostWindow tracks per-host traffic for error_spike and traffic_anomaly.
// `events` is the rolling timestamp list used by the anomaly rule; fiveXX is
// a narrow counter for the error_spike rule so a busy but healthy host does
// not force the anomaly rule to walk a large slice on every 5xx.
type hostWindow struct {
	events           []time.Time
	fiveXX           []time.Time
	lastActive       time.Time
	lastAnomalyCheck time.Time
}

// actorWindow is keyed by JWT identity when available, falling back to IP.
// data_export_burst uses it so "a logged-in user downloaded 50 PDFs in a
// minute" registers as one actor even if they rotate IPs.
type actorWindow struct {
	exports           []time.Time
	exportSamplePaths []string
	lastActive        time.Time
}

func New(sink AlertSink, configFn ConfigFunc) *Engine {
	return &Engine{
		sink:        sink,
		configFn:    configFn,
		quit:        make(chan struct{}),
		stopped:     make(chan struct{}),
		ipCounts:    make(map[string]*ipWindow),
		hostCounts:  make(map[string]*hostWindow),
		actorCounts: make(map[string]*actorWindow),
	}
}

// Run subscribes to the pipeline and processes entries.
func (e *Engine) Run(pipeline *logger.Pipeline) {
	ch := pipeline.Subscribe()

	go e.cleanup()

	go func() {
		defer close(e.stopped)
		defer pipeline.Unsubscribe(ch)

		for {
			select {
			case entry, ok := <-ch:
				if !ok {
					return
				}
				e.process(entry)
			case <-e.quit:
				return
			}
		}
	}()

	slog.Info("correlation engine started")
}

// Stop shuts down the engine gracefully.
func (e *Engine) Stop() {
	close(e.quit)
	<-e.stopped
	slog.Info("correlation engine stopped")
}

func (e *Engine) process(entry logger.Entry) {
	cfg := e.configFn()
	now := entry.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	ip := entry.ClientIP
	status := entry.ResponseStatus
	host := entry.Host
	reqPath := entry.Path

	e.mu.Lock()
	defer e.mu.Unlock()

	// --- Rule 1: path_scan — same IP, N distinct 404 paths in window ---
	if status == 404 && ip != "" && cfg.PathScanDistinct > 0 {
		w := e.getOrCreateIP(ip)
		w.notFound = appendPrune(w.notFound, now, cfg.PathScanWindow)
		if w.paths404 == nil {
			w.paths404 = make(map[string]struct{})
		}
		w.paths404[reqPath] = struct{}{}
		// If the whole window was pruned away the distinct-path set should
		// reset too — otherwise it would grow without bound for slow scanners.
		if len(w.notFound) == 1 {
			w.paths404 = map[string]struct{}{reqPath: {}}
		}
		if len(w.paths404) >= cfg.PathScanDistinct && len(w.notFound) >= cfg.PathScanDistinct {
			e.emit(Alert{
				Rule:        "path_scan",
				Severity:    "warning",
				Title:       "Path enumeration detected",
				Detail:      attachIdentity(map[string]any{"ip": ip, "distinct_paths": len(w.paths404), "count": len(w.notFound)}, entry),
				SourceIP:    ip,
				Host:        host,
				Fingerprint: "path_scan:" + ip,
			})
			w.notFound = w.notFound[:0]
			w.paths404 = make(map[string]struct{})
		}
	}

	// --- Rule 2: auth_brute_force — same IP, N auth failures in window ---
	// Django / simplejwt apps return 400 on bad credentials for enumeration
	// resistance, so a pure 401/403 count would never fire for those apps.
	// We additionally treat 400 as an auth failure when the request hit one
	// of the configured login endpoints.
	if ip != "" && cfg.AuthBruteCount > 0 && !entry.WafBlocked {
		isAuthFailure := status == 401 || status == 403
		if !isAuthFailure && status == 400 && pathExactMatch(reqPath, cfg.AuthPaths) {
			isAuthFailure = true
		}
		if isAuthFailure {
			w := e.getOrCreateIP(ip)
			w.authFail = appendPrune(w.authFail, now, cfg.AuthBruteWindow)
			if len(w.authFail) >= cfg.AuthBruteCount {
				e.emit(Alert{
					Rule:        "auth_brute_force",
					Severity:    "critical",
					Title:       "Authentication brute force detected",
					Detail:      attachIdentity(map[string]any{"ip": ip, "count": len(w.authFail), "status": status, "path": reqPath}, entry),
					SourceIP:    ip,
					Host:        host,
					Fingerprint: "auth_brute_force:" + ip,
				})
				w.authFail = w.authFail[:0]
			}
		}
	}

	// --- Rule 3: error_spike — same host, N 5xx responses in window ---
	// Rate-limited via the alert manager's cooldown (no longer NoCooldown).
	if status >= 500 && host != "" && cfg.ErrorSpikeCount > 0 {
		w := e.getOrCreateHost(host)
		w.fiveXX = appendPrune(w.fiveXX, now, cfg.ErrorSpikeWindow)
		if len(w.fiveXX) >= cfg.ErrorSpikeCount {
			e.emit(Alert{
				Rule:        "error_spike",
				Severity:    "critical",
				Title:       "5xx error spike detected",
				Detail:      attachIdentity(map[string]any{"host": host, "count": len(w.fiveXX), "window_seconds": int(cfg.ErrorSpikeWindow.Seconds())}, entry),
				Host:        host,
				Fingerprint: "error_spike:" + host,
			})
			w.fiveXX = w.fiveXX[:0]
		}
	}

	// --- Rule 4: waf_repeat_offender — same IP, N WAF blocks in window ---
	if entry.WafBlocked && ip != "" && cfg.WafRepeatCount > 0 {
		w := e.getOrCreateIP(ip)
		w.wafBlocks = appendPrune(w.wafBlocks, now, cfg.WafRepeatWindow)
		if len(w.wafBlocks) >= cfg.WafRepeatCount {
			e.emit(Alert{
				Rule:        "waf_repeat_offender",
				Severity:    "warning",
				Title:       "Repeated WAF violations from same IP",
				Detail:      attachIdentity(map[string]any{"ip": ip, "count": len(w.wafBlocks)}, entry),
				SourceIP:    ip,
				Host:        host,
				Fingerprint: "waf_repeat:" + ip,
			})
			w.wafBlocks = w.wafBlocks[:0]
		}
	}

	// --- Rule 5: traffic_anomaly — host current RPS vs baseline ---
	// Baseline window is events older than the current window; they do not
	// overlap. Low-traffic hosts (baselineCount < MinBaseline) are skipped
	// so "1 request → 10 requests" doesn't trip a 10× ratio alert.
	if cfg.AnomalyEnabled && host != "" && cfg.AnomalyBaseline > cfg.AnomalyCurrent {
		w := e.getOrCreateHost(host)
		w.events = appendPrune(w.events, now, cfg.AnomalyBaseline)
		// Throttle re-evaluation to once per 5s per host — a busy host can
		// otherwise walk a 10-minute timestamp slice per request.
		if now.Sub(w.lastAnomalyCheck) >= 5*time.Second {
			w.lastAnomalyCheck = now
			currentCutoff := now.Add(-cfg.AnomalyCurrent)
			var currentCount, baselineCount int
			for _, t := range w.events {
				if t.Before(currentCutoff) {
					baselineCount++
				} else {
					currentCount++
				}
			}
			baselineSeconds := (cfg.AnomalyBaseline - cfg.AnomalyCurrent).Seconds()
			if baselineSeconds > 0 && baselineCount >= cfg.AnomalyMinBaseline {
				baselineRPS := float64(baselineCount) / baselineSeconds
				currentRPS := float64(currentCount) / cfg.AnomalyCurrent.Seconds()
				if baselineRPS > 0 && currentRPS > baselineRPS*cfg.AnomalyRatio {
					e.emit(Alert{
						Rule:     "traffic_anomaly",
						Severity: "warning",
						Title:    "Traffic volume anomaly",
						Detail: attachIdentity(map[string]any{
							"host":         host,
							"baseline_rps": round2(baselineRPS),
							"current_rps":  round2(currentRPS),
							"ratio":        round2(currentRPS / baselineRPS),
						}, entry),
						Host:        host,
						Fingerprint: "traffic_anomaly:" + host,
					})
				}
			}
		}
	}

	// --- Rule 6: sensitive_access — configured paths hit past threshold ---
	// Uses glob matching (path.Match); empty SensitivePaths disables the rule.
	if len(cfg.SensitivePaths) > 0 && ip != "" && pathGlobMatch(reqPath, cfg.SensitivePaths) {
		w := e.getOrCreateIP(ip)
		w.sensitive = appendPrune(w.sensitive, now, cfg.SensitiveWindow)
		w.sensitiveSamplePaths = addSample(w.sensitiveSamplePaths, reqPath, 5)
		if len(w.sensitive) >= cfg.SensitiveThreshold {
			e.emit(Alert{
				Rule:     "sensitive_access",
				Severity: "warning",
				Title:    "Heavy access to sensitive endpoints",
				Detail: attachIdentity(map[string]any{
					"ip":          ip,
					"count":       len(w.sensitive),
					"sample_paths": w.sensitiveSamplePaths,
				}, entry),
				SourceIP:    ip,
				Host:        host,
				Fingerprint: "sensitive_access:" + ip,
			})
			w.sensitive = w.sensitive[:0]
			w.sensitiveSamplePaths = nil
		}
	}

	// --- Rule 7: data_export_burst — per-actor export volume ---
	// Keyed by JWT identity (sub/user_id/email) when present — rotating IPs
	// won't split an insider's footprint across actors. Falls back to IP.
	if cfg.ExportPattern != nil && cfg.ExportPattern.MatchString(reqPath) {
		actor := resolveActor(entry, ip)
		if actor != "" {
			w := e.getOrCreateActor(actor)
			w.exports = appendPrune(w.exports, now, cfg.ExportWindow)
			w.exportSamplePaths = addSample(w.exportSamplePaths, reqPath, 5)
			if len(w.exports) >= cfg.ExportThreshold {
				e.emit(Alert{
					Rule:     "data_export_burst",
					Severity: "warning",
					Title:    "Burst of data export / download",
					Detail: attachIdentity(map[string]any{
						"actor":        actor,
						"count":        len(w.exports),
						"sample_paths": w.exportSamplePaths,
					}, entry),
					SourceIP:    ip,
					Host:        host,
					Fingerprint: "data_export_burst:" + actor,
				})
				w.exports = w.exports[:0]
				w.exportSamplePaths = nil
			}
		}
	}
}

func (e *Engine) getOrCreateIP(ip string) *ipWindow {
	w, ok := e.ipCounts[ip]
	if !ok {
		w = &ipWindow{}
		e.ipCounts[ip] = w
	}
	w.lastActive = time.Now()
	return w
}

func (e *Engine) getOrCreateHost(host string) *hostWindow {
	w, ok := e.hostCounts[host]
	if !ok {
		w = &hostWindow{}
		e.hostCounts[host] = w
	}
	w.lastActive = time.Now()
	return w
}

func (e *Engine) getOrCreateActor(actor string) *actorWindow {
	w, ok := e.actorCounts[actor]
	if !ok {
		w = &actorWindow{}
		e.actorCounts[actor] = w
	}
	w.lastActive = time.Now()
	return w
}

func (e *Engine) emit(alert Alert) {
	if e.sink != nil {
		e.sink.HandleAlert(context.Background(), alert)
	}
}

// attachIdentity merges the request's JWT identity claims into an alert
// detail map so the UI can render "alice@foo.com" next to the IP instead of
// making the admin click through to a single log to find out who did it.
// No-op when the request is anonymous; non-destructive otherwise (never
// overwrites keys already set by the rule).
func attachIdentity(detail map[string]any, entry logger.Entry) map[string]any {
	if entry.UserIdentity == nil || len(entry.UserIdentity.Claims) == 0 {
		return detail
	}
	if detail == nil {
		detail = make(map[string]any)
	}
	setIf := func(key, claim string) {
		if _, exists := detail[key]; exists {
			return
		}
		if v := entry.UserIdentity.Claims[claim]; v != "" {
			detail[key] = v
		}
	}
	setIf("actor_email", "email")
	setIf("actor_name", "name")
	setIf("actor_sub", "sub")
	if _, ok := detail["actor_verified"]; !ok {
		detail["actor_verified"] = entry.UserIdentity.Verified
	}
	return detail
}

// cleanup bounds engine memory by dropping windows that have not seen an
// event for a while. The TTLs are generous relative to each rule's window
// so a slow scanner's state isn't dropped mid-attack.
func (e *Engine) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.mu.Lock()
			now := time.Now()
			for ip, w := range e.ipCounts {
				if now.Sub(w.lastActive) > 15*time.Minute {
					delete(e.ipCounts, ip)
				}
			}
			for host, w := range e.hostCounts {
				if now.Sub(w.lastActive) > 30*time.Minute {
					delete(e.hostCounts, host)
				}
			}
			for actor, w := range e.actorCounts {
				if now.Sub(w.lastActive) > 15*time.Minute {
					delete(e.actorCounts, actor)
				}
			}
			e.mu.Unlock()
		case <-e.quit:
			return
		}
	}
}

// appendPrune keeps timestamps within the window and appends the new event.
func appendPrune(events []time.Time, now time.Time, window time.Duration) []time.Time {
	cutoff := now.Add(-window)
	start := 0
	for start < len(events) && events[start].Before(cutoff) {
		start++
	}
	if start > 0 {
		events = events[start:]
	}
	return append(events, now)
}

// pathExactMatch returns true if req matches any of patterns exactly.
// Trailing-slash differences are ignored to tolerate both /api/auth/login
// and /api/auth/login/ being in the same list.
func pathExactMatch(req string, patterns []string) bool {
	reqTrim := trimTrailingSlash(req)
	for _, p := range patterns {
		if trimTrailingSlash(p) == reqTrim {
			return true
		}
	}
	return false
}

// pathGlobMatch runs each configured glob against the request path using
// stdlib path.Match. "*" matches one segment (no slashes), so a pattern
// like /api/applications/*/generate_pdf_report/ matches
// /api/applications/123/generate_pdf_report/ but not deeper hierarchies.
// Malformed patterns log a warning and are treated as non-matching.
func pathGlobMatch(req string, patterns []string) bool {
	for _, p := range patterns {
		ok, err := path.Match(p, req)
		if err != nil {
			slog.Warn("correlation: invalid glob pattern", "pattern", p, "error", err)
			continue
		}
		if ok {
			return true
		}
	}
	return false
}

func trimTrailingSlash(s string) string {
	if len(s) > 1 && s[len(s)-1] == '/' {
		return s[:len(s)-1]
	}
	return s
}

// resolveActor returns a stable key for a request. JWT identity wins so the
// same user rotating IPs still looks like one actor. Without identity the
// rule still fires but at IP granularity.
func resolveActor(entry logger.Entry, ip string) string {
	if entry.UserIdentity != nil {
		for _, key := range []string{"sub", "user_id", "email"} {
			if v, ok := entry.UserIdentity.Claims[key]; ok && v != "" {
				return "user:" + v
			}
		}
	}
	if ip != "" {
		return "ip:" + ip
	}
	return ""
}

func addSample(samples []string, s string, cap int) []string {
	for _, existing := range samples {
		if existing == s {
			return samples
		}
	}
	if len(samples) >= cap {
		return samples
	}
	return append(samples, s)
}

func round2(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}
