package correlation

import (
	"context"
	"log/slog"
	"sync"
	"time"

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
	NoCooldown  bool // if true, cooldown is skipped and every occurrence is notified
}

// AlertSink receives alerts produced by the correlation engine.
type AlertSink interface {
	HandleAlert(ctx context.Context, alert Alert)
}

// Engine subscribes to the log pipeline and applies lightweight
// in-memory correlation rules to detect patterns.
type Engine struct {
	sink    AlertSink
	quit    chan struct{}
	stopped chan struct{}

	mu       sync.Mutex
	ipCounts map[string]*ipWindow   // IP → sliding window counters
	hostErrs map[string]*countWindow // host → 5xx counter
}

// ipWindow tracks per-IP counters for multiple rules.
type ipWindow struct {
	notFound   []time.Time // 404 timestamps
	authFail   []time.Time // 401/403 timestamps
	wafBlocks  []time.Time // WAF block timestamps
	paths404   map[string]struct{} // distinct 404 paths in window
	lastActive time.Time
}

// countWindow tracks a simple event count in a time window.
type countWindow struct {
	events     []time.Time
	lastActive time.Time
}

func New(sink AlertSink) *Engine {
	return &Engine{
		sink:     sink,
		quit:     make(chan struct{}),
		stopped:  make(chan struct{}),
		ipCounts: make(map[string]*ipWindow),
		hostErrs: make(map[string]*countWindow),
	}
}

// Run subscribes to the pipeline and processes entries.
// Call Stop() to shut down.
func (e *Engine) Run(pipeline *logger.Pipeline) {
	ch := pipeline.Subscribe()

	// Periodic cleanup of stale windows
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
	now := entry.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	ip := entry.ClientIP
	status := entry.ResponseStatus
	host := entry.Host

	e.mu.Lock()
	defer e.mu.Unlock()

	// Rule 1: Path Scan Detection — 10+ distinct 404 paths from same IP in 2 minutes
	if status == 404 && ip != "" {
		w := e.getOrCreateIP(ip)
		w.notFound = appendPrune(w.notFound, now, 2*time.Minute)
		if w.paths404 == nil {
			w.paths404 = make(map[string]struct{})
		}
		w.paths404[entry.Path] = struct{}{}
		// Prune old paths if window was fully reset
		if len(w.notFound) == 1 {
			w.paths404 = map[string]struct{}{entry.Path: {}}
		}
		if len(w.paths404) >= 10 && len(w.notFound) >= 10 {
			e.emit(Alert{
				Rule:        "path_scan",
				Severity:    "warning",
				Title:       "Path enumeration detected",
				Detail:      map[string]any{"ip": ip, "distinct_paths": len(w.paths404), "count": len(w.notFound)},
				SourceIP:    ip,
				Host:        host,
				Fingerprint: "path_scan:" + ip,
			})
			// Reset to avoid repeated alerts
			w.notFound = w.notFound[:0]
			w.paths404 = make(map[string]struct{})
		}
	}

	// Rule 2: Auth Brute Force — 5+ 401/403 from same IP in 2 minutes
	if (status == 401 || status == 403) && ip != "" && !entry.WafBlocked {
		w := e.getOrCreateIP(ip)
		w.authFail = appendPrune(w.authFail, now, 2*time.Minute)
		if len(w.authFail) >= 5 {
			e.emit(Alert{
				Rule:        "auth_brute_force",
				Severity:    "critical",
				Title:       "Authentication brute force detected",
				Detail:      map[string]any{"ip": ip, "count": len(w.authFail)},
				SourceIP:    ip,
				Host:        host,
				Fingerprint: "auth_brute_force:" + ip,
			})
			w.authFail = w.authFail[:0]
		}
	}

	// Rule 3: 5xx Error — every single 5xx triggers an alert, no cooldown
	if status >= 500 && host != "" {
		e.emit(Alert{
			Rule:        "error_spike",
			Severity:    "critical",
			Title:       "5xx error detected",
			Detail:      map[string]any{"host": host, "status": status},
			Host:        host,
			Fingerprint: "error_spike:" + host,
			NoCooldown:  true,
		})
	}

	// Rule 4: WAF Repeat Offender — 3+ WAF blocks from same IP in 5 minutes
	if entry.WafBlocked && ip != "" {
		w := e.getOrCreateIP(ip)
		w.wafBlocks = appendPrune(w.wafBlocks, now, 5*time.Minute)
		if len(w.wafBlocks) >= 3 {
			e.emit(Alert{
				Rule:        "waf_repeat_offender",
				Severity:    "warning",
				Title:       "Repeated WAF violations from same IP",
				Detail:      map[string]any{"ip": ip, "count": len(w.wafBlocks)},
				SourceIP:    ip,
				Host:        host,
				Fingerprint: "waf_repeat:" + ip,
			})
			w.wafBlocks = w.wafBlocks[:0]
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

func (e *Engine) getOrCreateHost(host string) *countWindow {
	w, ok := e.hostErrs[host]
	if !ok {
		w = &countWindow{}
		e.hostErrs[host] = w
	}
	w.lastActive = time.Now()
	return w
}

func (e *Engine) emit(alert Alert) {
	if e.sink != nil {
		e.sink.HandleAlert(context.Background(), alert)
	}
}

// cleanup periodically removes stale entries to bound memory.
func (e *Engine) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.mu.Lock()
			now := time.Now()
			for ip, w := range e.ipCounts {
				if now.Sub(w.lastActive) > 10*time.Minute {
					delete(e.ipCounts, ip)
				}
			}
			for host, w := range e.hostErrs {
				if now.Sub(w.lastActive) > 5*time.Minute {
					delete(e.hostErrs, host)
				}
			}
			e.mu.Unlock()
		case <-e.quit:
			return
		}
	}
}

// appendPrune appends a timestamp and prunes events older than the window.
func appendPrune(events []time.Time, now time.Time, window time.Duration) []time.Time {
	cutoff := now.Add(-window)
	// Prune from front
	start := 0
	for start < len(events) && events[start].Before(cutoff) {
		start++
	}
	if start > 0 {
		events = events[start:]
	}
	return append(events, now)
}
