package alerting

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"muvon/internal/correlation"
	"muvon/internal/db"
)

// Config holds alerting configuration, loaded from the atomic config holder.
type Config struct {
	Enabled         bool
	SlackWebhook    string
	SMTPHost        string
	SMTPPort        int
	SMTPUsername    string
	SMTPPassword    string
	SMTPFrom        string
	SMTPTo          string
	CooldownSeconds int
}

// ConfigFunc returns the current alerting configuration.
type ConfigFunc func() Config

// Manager handles alert persistence, cooldown, and notification dispatch.
type Manager struct {
	database  *db.DB
	configFn  ConfigFunc
	notifiers []Notifier

	// In-memory cooldown is a fast-path cache that lets a single node skip
	// the DB round-trip when the same fingerprint re-fires in quick
	// succession. The DB remains the source of truth — multi-node cooldown
	// and per-row occurrence counting happen there.
	cooldowns sync.Map
	quit      chan struct{}
	stopped   chan struct{}
}

// Notifier sends alerts to an external channel.
type Notifier interface {
	Name() string
	Send(ctx context.Context, alert correlation.Alert) error
}

func NewManager(database *db.DB, configFn ConfigFunc) *Manager {
	m := &Manager{
		database: database,
		configFn: configFn,
		quit:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
	return m
}

// AddNotifier adds a notification channel.
func (m *Manager) AddNotifier(n Notifier) {
	m.notifiers = append(m.notifiers, n)
}

// Start begins the cooldown cleanup goroutine.
func (m *Manager) Start() {
	go m.cleanupLoop()
	slog.Info("alerting manager started")
}

// Stop shuts down the manager.
func (m *Manager) Stop() {
	close(m.quit)
	<-m.stopped
	slog.Info("alerting manager stopped")
}

// HandleAlert implements correlation.AlertSink.
//
// The flow is:
//
//  1. Check the in-memory cooldown cache. Hit → we know (locally) a
//     notification just went out; skip the DB trip and only record the
//     occurrence. (The DB-backed path below would give the same answer, at
//     the cost of a lookup.)
//  2. Miss → ask UpsertAlert whether this fingerprint is already active
//     somewhere (any node). If yes, it bumps occurrences; if no, it inserts
//     a fresh row. Either way it reports whether we should notify.
//  3. If we should notify, run every registered notifier. Failures are
//     logged but do not revert the DB state — better to over-record a
//     delivery failure than to risk a duplicate Slack message.
//
// Cooldown=0 disables grouping entirely (old behavior, useful for tests).
func (m *Manager) HandleAlert(ctx context.Context, alert correlation.Alert) {
	cfg := m.configFn()
	cooldown := time.Duration(cfg.CooldownSeconds) * time.Second

	detailJSON, _ := json.Marshal(alert.Detail)
	rec := db.AlertRecord{
		Rule:        alert.Rule,
		Severity:    alert.Severity,
		Title:       alert.Title,
		Detail:      detailJSON,
		SourceIP:    alert.SourceIP,
		Host:        alert.Host,
		Fingerprint: alert.Fingerprint,
	}

	// Fast path: if we recently notified this fingerprint on this node,
	// just record the occurrence and skip notification dispatch.
	inCooldown := cfg.Enabled && cfg.CooldownSeconds > 0 && m.isCoolingDown(alert.Fingerprint, cfg.CooldownSeconds)

	notifyRequested := cfg.Enabled && !inCooldown
	result, err := m.database.UpsertAlert(ctx, rec, cooldown, notifyRequested)
	if err != nil {
		slog.Error("alerting: upsert failed", "error", err, "rule", alert.Rule)
		return
	}

	if !result.ShouldNotify {
		// Either cooldown was active (in-memory or DB) or alerting is
		// disabled. Either way, the event was persisted; nothing to send.
		return
	}

	if m.dispatch(ctx, alert) {
		m.setCooldown(alert.Fingerprint)
	}
}

func (m *Manager) dispatch(ctx context.Context, alert correlation.Alert) bool {
	sent := false
	for _, n := range m.notifiers {
		if err := n.Send(ctx, alert); err != nil {
			slog.Error("notification failed", "notifier", n.Name(), "error", err)
		} else {
			sent = true
		}
	}
	return sent
}

func (m *Manager) isCoolingDown(fingerprint string, cooldownSeconds int) bool {
	if cooldownSeconds <= 0 {
		return false
	}
	v, ok := m.cooldowns.Load(fingerprint)
	if !ok {
		return false
	}
	lastTime := v.(time.Time)
	return time.Since(lastTime) < time.Duration(cooldownSeconds)*time.Second
}

func (m *Manager) setCooldown(fingerprint string) {
	m.cooldowns.Store(fingerprint, time.Now())
}

func (m *Manager) cleanupLoop() {
	defer close(m.stopped)
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Keep the cache from growing unbounded: anything older than 2×
			// the longest reasonable cooldown is safe to forget — the DB
			// would handle it anyway.
			cutoff := time.Now().Add(-1 * time.Hour)
			m.cooldowns.Range(func(key, value any) bool {
				if value.(time.Time).Before(cutoff) {
					m.cooldowns.Delete(key)
				}
				return true
			})
		case <-m.quit:
			return
		}
	}
}
