package alerting

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"muvon/internal/alertrules"
	"muvon/internal/correlation"
	"muvon/internal/db"
)

// Manager turns rule firings into alerts and queues the notifications they
// call for. Sending is the Dispatcher's job; the Manager only writes, in the
// same transaction as the alert, so a notification exists exactly when the
// alert change that caused it does.
type Manager struct {
	database *db.DB
	store    *Store
	wake     func()
}

// NewManager wires a manager to its rule store.
func NewManager(database *db.DB, store *Store) *Manager {
	return &Manager{database: database, store: store, wake: func() {}}
}

// SetWake registers what to call once queued notifications are committed,
// normally Dispatcher.Wake, so they go out without waiting for its next tick.
func (m *Manager) SetWake(fn func()) {
	if fn != nil {
		m.wake = fn
	}
}

// Wake signals that notifications were committed.
func (m *Manager) Wake() { m.wake() }

// HandleAlert implements correlation.AlertSink for builtin detections: the
// HTTP correlation rules and the certificate watch. How the alert is routed
// comes from the builtin's rule row. A builtin the operator disabled records
// nothing; one not synced yet records without notifying.
func (m *Manager) HandleAlert(ctx context.Context, a correlation.Alert) {
	snap := m.store.Get()
	rule, known := snap.Builtins[a.Rule]
	if known && !rule.Enabled {
		return
	}

	detail, err := json.Marshal(a.Detail)
	if err != nil {
		slog.Error("alerting: encode alert detail", "rule", a.Rule, "error", err)
		return
	}
	ev := db.AlertEvent{
		Rule:        a.Rule,
		RuleName:    a.Rule,
		Severity:    a.Severity,
		Title:       a.Title,
		Detail:      detail,
		SourceIP:    a.SourceIP,
		Host:        a.Host,
		Fingerprint: a.Fingerprint,
		Delivery:    alertrules.DeliveryNone,
		Occurrences: 1,
		At:          time.Now(),
	}
	var channels []alertrules.Channel
	if known {
		ev.RuleID = rule.ID
		ev.RuleName = rule.Name
		ev.Delivery = rule.Delivery
		ev.RemindAfter = time.Duration(rule.RemindMinutes) * time.Minute
		channels = snap.ChannelsFor(rule)
	}

	queued := false
	err = pgx.BeginFunc(ctx, m.database.Pool, func(tx pgx.Tx) error {
		_, q, err := m.Raise(ctx, tx, ev, channels)
		queued = q
		return err
	})
	if err != nil {
		slog.Error("alerting: raise alert failed", "rule", a.Rule, "error", err)
		return
	}
	if queued {
		m.wake()
	}
}

// Raise merges an event into its alert and queues what that change should
// notify: a new alert, an escalation, or a test. It reports whether anything
// was queued so the caller can wake the dispatcher after committing.
func (m *Manager) Raise(ctx context.Context, tx pgx.Tx, ev db.AlertEvent, channels []alertrules.Channel) (db.RaiseResult, bool, error) {
	res, err := db.RaiseAlert(ctx, tx, ev)
	if err != nil {
		return res, false, err
	}
	kind := notificationKind(ev, res)
	if kind == "" || len(channels) == 0 {
		return res, false, nil
	}
	if err := db.QueueAlertDeliveries(ctx, tx, []string{res.AlertID}, channels, kind, res.Severity); err != nil {
		return res, false, err
	}
	return res, true, nil
}

// notificationKind decides whether an alert change is news. A test always is;
// otherwise only instant delivery notifies, and only when the alert opens or
// its severity rises. Repeats of an open alert are counted, not sent.
func notificationKind(ev db.AlertEvent, res db.RaiseResult) string {
	switch {
	case ev.IsTest:
		return db.DeliveryTest
	case ev.Delivery != alertrules.DeliveryInstant:
		return ""
	case res.Opened:
		return db.DeliveryOpened
	case res.Escalated:
		return db.DeliveryEscalated
	}
	return ""
}

// reminderBatch bounds how many reminders one pass queues.
const reminderBatch = 100

// RunReminders re-notifies critical alerts that stay unacknowledged, on each
// rule's interval, until ctx ends.
func (m *Manager) RunReminders(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.sendDueReminders(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("alerting: reminder pass failed", "error", err)
			}
		}
	}
}

func (m *Manager) sendDueReminders(ctx context.Context) error {
	snap := m.store.Get()
	queued := false
	err := pgx.BeginFunc(ctx, m.database.Pool, func(tx pgx.Tx) error {
		due, err := db.ClaimDueReminders(ctx, tx, reminderBatch)
		if err != nil {
			return err
		}
		now := time.Now()
		for _, r := range due {
			rule, ok := snap.Rules[r.RuleID]
			if !ok {
				rule, ok = snap.Builtins[r.Rule]
			}
			// The rule may have changed since the alert opened; its
			// current settings decide whether reminders continue.
			if !ok || !rule.Enabled || rule.Delivery != alertrules.DeliveryInstant ||
				rule.RemindMinutes <= 0 || r.Severity != alertrules.SeverityCritical {
				if err := db.SetAlertReminder(ctx, tx, r.AlertID, nil); err != nil {
					return err
				}
				continue
			}
			if channels := snap.ChannelsFor(rule); len(channels) > 0 {
				if err := db.QueueAlertDeliveries(ctx, tx, []string{r.AlertID}, channels, db.DeliveryReminder, r.Severity); err != nil {
					return err
				}
				queued = true
			}
			next := now.Add(time.Duration(rule.RemindMinutes) * time.Minute)
			if err := db.SetAlertReminder(ctx, tx, r.AlertID, &next); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil && queued {
		m.wake()
	}
	return err
}
