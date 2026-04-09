package waf

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"time"

	"muvon/internal/db"
)

// Engine is the main WAF orchestrator, integrated directly into the reverse proxy.
// It replaces the external muWAF HTTP client with in-process, synchronous inspection.
type Engine struct {
	RuleCache  *RuleCache
	IPState    *IPStateManager
	VTChecker  *VTChecker
	config     atomic.Pointer[WafConfig]
	database   *db.DB
	eventCh    chan WafEvent
	quit       chan struct{}
}

// NewEngine creates a new WAF engine.
func NewEngine(database *db.DB) *Engine {
	cfg := DefaultWafConfig()
	e := &Engine{
		database: database,
		eventCh:  make(chan WafEvent, 10000),
		quit:     make(chan struct{}),
	}
	e.config.Store(&cfg)
	e.RuleCache = NewRuleCache(database, cfg.PatternCacheTTLSeconds)
	e.IPState = NewIPStateManager(database)
	e.VTChecker = NewVTChecker(database, cfg.VTApiKey, cfg.VTTimeoutSeconds, cfg.VTScoreContribution, cfg.VTCacheTTLHours)
	return e
}

// Start initializes all sub-components and begins background goroutines.
func (e *Engine) Start(ctx context.Context) error {
	// Load rules
	if err := e.RuleCache.Refresh(ctx); err != nil {
		slog.Error("waf engine: failed to load rules", "error", err)
		// Non-fatal: engine works with empty ruleset
	}

	// Load IP state
	if err := e.IPState.Start(ctx); err != nil {
		slog.Error("waf engine: failed to start IP state", "error", err)
	}

	// Start event logger
	go e.eventLogger()

	slog.Info("waf engine started",
		"rules", e.RuleCache.RuleCount(),
		"ip_states", len(e.IPState.states))

	return nil
}

// Stop gracefully shuts down the engine.
func (e *Engine) Stop(ctx context.Context) {
	close(e.quit)
	e.IPState.Stop(ctx)

	// Drain event channel
	close(e.eventCh)
	slog.Info("waf engine stopped")
}

// ReloadConfig updates the WAF configuration atomically.
func (e *Engine) ReloadConfig(cfg *WafConfig) {
	e.config.Store(cfg)
	e.RuleCache.ttl = time.Duration(cfg.PatternCacheTTLSeconds) * time.Second
	e.VTChecker.UpdateConfig(cfg.VTApiKey, cfg.VTTimeoutSeconds, cfg.VTScoreContribution, cfg.VTCacheTTLHours)
	slog.Info("waf config reloaded")
}

// GetConfig returns the current WAF configuration.
func (e *Engine) GetConfig() *WafConfig {
	return e.config.Load()
}

// Inspect performs synchronous WAF inspection on an incoming request.
// This is the main entry point called from the proxy handler.
func (e *Engine) Inspect(ctx context.Context, req InspectRequest) InspectResult {
	start := time.Now()
	cfg := e.config.Load()

	// 1. Global WAF check
	if !cfg.EnabledGlobal {
		return InspectResult{Action: ActionAllow}
	}

	detectionOnly := cfg.DetectionOnly || req.DetectionOnly

	// 2. IP ban check (sub-microsecond, in-memory)
	if banned, reason := e.IPState.IsBanned(req.ClientIP); banned {
		result := InspectResult{
			Action:        ActionBlock,
			BlockReason:   reason,
			DetectionOnly: detectionOnly,
			ProcessingUs:  time.Since(start).Microseconds(),
		}
		if !detectionOnly {
			return result
		}
		// In detection-only mode, log but don't block
	}

	// 3. Whitelist check
	if e.IPState.IsWhitelisted(req.ClientIP) {
		return InspectResult{Action: ActionAllow, ProcessingUs: time.Since(start).Microseconds()}
	}

	// 4. Ensure rule cache is fresh
	e.RuleCache.EnsureFresh(ctx)

	// 5. Extract request parts
	parts := ExtractParts(req, cfg.MaxBodyInspectBytes)

	// 6. Pattern matching (AC + regex against all normalized variations)
	matches := MatchAll(e.RuleCache, parts, req.RouteID, cfg.NormalizationMaxIter)

	// 7. Score this request
	requestScore := ScoreRequest(matches)

	// 8. Update IP cumulative score
	var ipScore float64
	if requestScore > 0 {
		ipScore = e.IPState.UpdateScore(req.ClientIP, requestScore, cfg)
	} else {
		state := e.IPState.GetOrCreate(req.ClientIP)
		ipScore = state.CumulativeScore
	}

	// 9. Determine action
	action := ActionAllow
	if requestScore > 0 {
		action = DetermineAction(ipScore, cfg)
	}

	// 10. Build result
	result := InspectResult{
		Action:        action,
		RequestScore:  requestScore,
		IPScore:       ipScore,
		Matches:       matches,
		BlockReason:   BuildBlockReason(matches),
		DetectionOnly: detectionOnly,
		ProcessingUs:  time.Since(start).Microseconds(),
	}

	// 11. Async VirusTotal check for suspicious IPs
	if requestScore > 0 {
		e.VTChecker.CheckAsync(req.ClientIP, e.IPState, cfg)
	}

	// 12. Log WAF event (async)
	if requestScore > 0 || action != ActionAllow {
		e.logEvent(req, result)
	}

	return result
}

// logEvent sends a WAF event to the async logger.
func (e *Engine) logEvent(req InspectRequest, result InspectResult) {
	event := WafEvent{
		Timestamp:     time.Now(),
		RequestID:     req.RequestID,
		ClientIP:      req.ClientIP,
		Host:          req.Host,
		Method:        req.Method,
		Path:          req.Path,
		RequestScore:  result.RequestScore,
		IPScore:       result.IPScore,
		Action:        result.Action,
		MatchedRules:  result.Matches,
		DetectionMode: result.DetectionOnly,
	}

	select {
	case e.eventCh <- event:
	default:
		slog.Warn("waf event channel full, dropping event")
	}
}

// eventLogger persists WAF events to the database in the background.
func (e *Engine) eventLogger() {
	for event := range e.eventCh {
		rulesJSON, _ := json.Marshal(event.MatchedRules)

		dbEvent := db.WafEvent{
			Timestamp:     event.Timestamp,
			RequestID:     event.RequestID,
			ClientIP:      event.ClientIP,
			Host:          event.Host,
			Method:        event.Method,
			Path:          event.Path,
			RequestScore:  event.RequestScore,
			IPScore:       event.IPScore,
			Action:        string(event.Action),
			MatchedRules:  rulesJSON,
			DetectionMode: event.DetectionMode,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := e.database.InsertWafEvent(ctx, dbEvent); err != nil {
			slog.Error("waf event insert failed", "error", err)
		}
		cancel()
	}
}
