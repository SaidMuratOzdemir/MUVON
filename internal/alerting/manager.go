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

	// Fingerprint-based cooldown: fingerprint → last alert time
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
// It persists the alert to DB and dispatches notifications with cooldown.
func (m *Manager) HandleAlert(ctx context.Context, alert correlation.Alert) {
	cfg := m.configFn()

	// Always persist to DB
	detailJSON, _ := json.Marshal(alert.Detail)
	notified := false

	if cfg.Enabled && (alert.NoCooldown || !m.isCoolingDown(alert.Fingerprint, cfg.CooldownSeconds)) {
		notified = m.dispatch(ctx, alert)
		if notified && !alert.NoCooldown {
			m.setCooldown(alert.Fingerprint)
		}
	}

	if err := m.database.InsertAlert(ctx, db.AlertRecord{
		Rule:        alert.Rule,
		Severity:    alert.Severity,
		Title:       alert.Title,
		Detail:      detailJSON,
		SourceIP:    alert.SourceIP,
		Host:        alert.Host,
		Fingerprint: alert.Fingerprint,
		Notified:    notified,
	}); err != nil {
		slog.Error("failed to persist alert", "error", err, "rule", alert.Rule)
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
			// Remove cooldowns older than 10 minutes (2x max reasonable cooldown)
			cutoff := time.Now().Add(-10 * time.Minute)
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
