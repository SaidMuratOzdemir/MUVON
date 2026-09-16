package alerting

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"muvon/internal/alertrules"
	"muvon/internal/correlation"
	"muvon/internal/db"
	"muvon/internal/secret"
	"muvon/internal/testpg"
)

type fixture struct {
	dbs   testpg.DBs
	box   *secret.Box
	store *Store
	mgr   *Manager
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dbs := testpg.Open(t)
	box, err := secret.NewBox("test-key")
	if err != nil {
		t.Fatalf("box: %v", err)
	}
	if _, err := dbs.Muvon.SyncBuiltinAlertRules(context.Background(), alertrules.BuiltinRules()); err != nil {
		t.Fatalf("sync builtins: %v", err)
	}
	store := NewStore(dbs.Dialog, box)
	if err := store.Load(context.Background()); err != nil {
		t.Fatalf("load store: %v", err)
	}
	return fixture{dbs: dbs, box: box, store: store, mgr: NewManager(dbs.Dialog, store)}
}

func (f fixture) slackChannel(t *testing.T, name string) alertrules.Channel {
	t.Helper()
	enc, err := f.box.Encrypt("https://hooks.example.com/services/T/B/X")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	c, err := f.dbs.Muvon.CreateAlertChannel(context.Background(), alertrules.Channel{
		Name: name, Kind: alertrules.ChannelSlack, Enabled: true, SlackWebhook: enc, DigestTimezone: "UTC",
	})
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}
	return c
}

func (f fixture) routeBuiltin(t *testing.T, key, delivery string, remind int, channelIDs ...string) {
	t.Helper()
	if err := f.store.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}
	rule := f.store.Get().Builtins[key]
	if _, err := f.dbs.Muvon.UpdateBuiltinRule(context.Background(), rule.ID, true, delivery, remind, channelIDs); err != nil {
		t.Fatalf("route builtin: %v", err)
	}
	if err := f.store.Load(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}
}

func raise(t *testing.T, f fixture, ev db.AlertEvent) db.RaiseResult {
	t.Helper()
	var res db.RaiseResult
	err := pgx.BeginFunc(context.Background(), f.dbs.Dialog.Pool, func(tx pgx.Tx) error {
		var err error
		res, err = db.RaiseAlert(context.Background(), tx, ev)
		return err
	})
	if err != nil {
		t.Fatalf("raise: %v", err)
	}
	return res
}

func countDeliveries(t *testing.T, f fixture, kind string) int {
	t.Helper()
	var n int
	if err := f.dbs.Dialog.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM dialog.alert_deliveries WHERE kind = $1`, kind).Scan(&n); err != nil {
		t.Fatalf("count deliveries: %v", err)
	}
	return n
}

func TestAlertLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	ev := db.AlertEvent{
		Rule: "event", RuleName: "Seal failed", Severity: alertrules.SeverityWarning, Title: "Seal failed",
		Fingerprint: "rule:1:job=42", Delivery: alertrules.DeliveryInstant, RemindAfter: time.Hour,
		Evidence: []db.AlertEvidence{{LogID: "a", Line: "first"}},
	}

	first := raise(t, f, ev)
	if !first.Opened {
		t.Fatal("first raise did not open an alert")
	}
	again := raise(t, f, ev)
	if again.Opened || again.Escalated || again.AlertID != first.AlertID {
		t.Fatalf("repeat = %+v, want a merge into %s", again, first.AlertID)
	}

	ev.Severity = alertrules.SeverityCritical
	ev.Title = "Seal failed repeatedly"
	up := raise(t, f, ev)
	if !up.Escalated || up.Severity != alertrules.SeverityCritical {
		t.Fatalf("escalation = %+v", up)
	}
	ev.Severity = alertrules.SeverityWarning
	if down := raise(t, f, ev); down.Severity != alertrules.SeverityCritical {
		t.Fatalf("a warning downgraded the open critical alert to %s", down.Severity)
	}

	a, err := f.dbs.Dialog.GetAlert(ctx, first.AlertID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if a.Occurrences != 4 || a.Title != "Seal failed repeatedly" || a.NextReminderAt == nil {
		t.Fatalf("alert = occurrences %d title %q reminder %v", a.Occurrences, a.Title, a.NextReminderAt)
	}
	var evidence []db.AlertEvidence
	_ = json.Unmarshal(a.Evidence, &evidence)
	if len(evidence) != 4 {
		t.Fatalf("evidence lines = %d, want 4", len(evidence))
	}

	acked, err := f.dbs.Dialog.AcknowledgeAlert(ctx, first.AlertID, "operator")
	if err != nil || !acked.Acknowledged || acked.NextReminderAt != nil {
		t.Fatalf("ack = %+v, %v; want acknowledged with reminders stopped", acked, err)
	}
	reopened := raise(t, f, ev)
	if !reopened.Opened || reopened.AlertID == first.AlertID {
		t.Fatalf("event after acknowledgement = %+v, want a new alert", reopened)
	}
}

func TestConcurrentRaisesConvergeOnOneAlert(t *testing.T) {
	f := newFixture(t)
	ev := db.AlertEvent{Rule: "event", Severity: alertrules.SeverityHigh, Title: "t", Fingerprint: "fp:race"}

	var wg sync.WaitGroup
	var mu sync.Mutex
	opened := 0
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := pgx.BeginFunc(context.Background(), f.dbs.Dialog.Pool, func(tx pgx.Tx) error {
				res, err := db.RaiseAlert(context.Background(), tx, ev)
				if err == nil && res.Opened {
					mu.Lock()
					opened++
					mu.Unlock()
				}
				return err
			})
			if err != nil {
				t.Errorf("raise: %v", err)
			}
		}()
	}
	wg.Wait()

	var rows, occurrences int
	if err := f.dbs.Dialog.Pool.QueryRow(context.Background(),
		`SELECT count(*), COALESCE(sum(occurrences), 0) FROM dialog.alerts WHERE fingerprint = 'fp:race'`).Scan(&rows, &occurrences); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 || occurrences != 12 || opened != 1 {
		t.Fatalf("rows = %d occurrences = %d opened = %d, want 1, 12, 1", rows, occurrences, opened)
	}
}

func TestBuiltinAlertsNotifyOnlyWhenNews(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	ch := f.slackChannel(t, "ops")

	brute := correlation.Alert{Rule: alertrules.BuiltinAuthBruteForce, Severity: alertrules.SeverityWarning,
		Title: "Brute force", SourceIP: "203.0.113.7", Fingerprint: "auth_brute_force:203.0.113.7"}

	// Unrouted builtin: recorded, not sent.
	f.mgr.HandleAlert(ctx, brute)
	if n := countDeliveries(t, f, db.DeliveryOpened); n != 0 {
		t.Fatalf("unrouted builtin queued %d deliveries", n)
	}

	f.routeBuiltin(t, alertrules.BuiltinAuthBruteForce, alertrules.DeliveryInstant, 240, ch.ID)
	if _, err := f.dbs.Dialog.Pool.Exec(ctx, `UPDATE dialog.alerts SET acknowledged = true, acknowledged_at = now()`); err != nil {
		t.Fatalf("ack: %v", err)
	}

	f.mgr.HandleAlert(ctx, brute)
	f.mgr.HandleAlert(ctx, brute)
	if n := countDeliveries(t, f, db.DeliveryOpened); n != 1 {
		t.Fatalf("opened deliveries = %d, want 1 for two firings", n)
	}
	brute.Severity = alertrules.SeverityCritical
	f.mgr.HandleAlert(ctx, brute)
	if n := countDeliveries(t, f, db.DeliveryEscalated); n != 1 {
		t.Fatalf("escalated deliveries = %d, want 1", n)
	}

	// A disabled builtin records nothing.
	rule := f.store.Get().Builtins[alertrules.BuiltinPathScan]
	if _, err := f.dbs.Muvon.UpdateBuiltinRule(ctx, rule.ID, false, alertrules.DeliveryInstant, 0, []string{ch.ID}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	_ = f.store.Load(ctx)
	f.mgr.HandleAlert(ctx, correlation.Alert{Rule: alertrules.BuiltinPathScan, Severity: "warning", Title: "scan", Fingerprint: "path_scan:x"})
	var n int
	_ = f.dbs.Dialog.Pool.QueryRow(ctx, `SELECT count(*) FROM dialog.alerts WHERE rule = 'path_scan'`).Scan(&n)
	if n != 0 {
		t.Fatalf("disabled builtin recorded %d alerts", n)
	}
}

type fakeSender struct {
	mu    sync.Mutex
	fails int
	sent  []Message
}

func (s *fakeSender) Send(_ context.Context, _ alertrules.Channel, m Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fails > 0 {
		s.fails--
		return errors.New("webhook unreachable")
	}
	s.sent = append(s.sent, m)
	return nil
}

func deliveryStatus(t *testing.T, f fixture, kind string) (status string, attempts int, lastError string) {
	t.Helper()
	if err := f.dbs.Dialog.Pool.QueryRow(context.Background(),
		`SELECT status, attempts, last_error FROM dialog.alert_deliveries WHERE kind = $1 ORDER BY created_at DESC LIMIT 1`, kind).
		Scan(&status, &attempts, &lastError); err != nil {
		t.Fatalf("delivery status: %v", err)
	}
	return
}

func TestDispatcherRetriesThenSends(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	ch := f.slackChannel(t, "ops")
	f.routeBuiltin(t, alertrules.BuiltinErrorSpike, alertrules.DeliveryInstant, 0, ch.ID)

	sender := &fakeSender{fails: 1}
	d := NewDispatcher(f.dbs.Dialog, f.store, func() SMTPConfig { return SMTPConfig{} }, "https://panel.example.com")
	d.senders[alertrules.ChannelSlack] = sender

	f.mgr.HandleAlert(ctx, correlation.Alert{Rule: alertrules.BuiltinErrorSpike, Severity: "critical", Title: "5xx", Host: "shop.example.com", Fingerprint: "error_spike:shop"})

	d.drain(ctx)
	if status, attempts, lastError := deliveryStatus(t, f, db.DeliveryOpened); status != db.DeliveryPending || attempts != 1 || lastError == "" {
		t.Fatalf("after a failed send: status %s attempts %d error %q", status, attempts, lastError)
	}

	// Make the retry due now.
	if _, err := f.dbs.Dialog.Pool.Exec(ctx, `UPDATE dialog.alert_deliveries SET next_attempt_at = now()`); err != nil {
		t.Fatalf("advance retry: %v", err)
	}
	d.drain(ctx)
	if status, _, _ := deliveryStatus(t, f, db.DeliveryOpened); status != db.DeliverySent {
		t.Fatalf("after retry: status %s, want sent", status)
	}
	if len(sender.sent) != 1 || sender.sent[0].Alerts[0].Host != "shop.example.com" {
		t.Fatalf("sent = %+v", sender.sent)
	}
	var notified *time.Time
	_ = f.dbs.Dialog.Pool.QueryRow(ctx, `SELECT notified_at FROM dialog.alerts LIMIT 1`).Scan(&notified)
	if notified == nil {
		t.Fatal("notified_at not stamped after a successful send")
	}
}

func TestDispatcherSkipsWhatNoLongerApplies(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	ch := f.slackChannel(t, "ops")
	f.routeBuiltin(t, alertrules.BuiltinErrorSpike, alertrules.DeliveryInstant, 60, ch.ID)
	sender := &fakeSender{}
	d := NewDispatcher(f.dbs.Dialog, f.store, func() SMTPConfig { return SMTPConfig{} }, "")
	d.senders[alertrules.ChannelSlack] = sender

	f.mgr.HandleAlert(ctx, correlation.Alert{Rule: alertrules.BuiltinErrorSpike, Severity: "critical", Title: "5xx", Fingerprint: "error_spike:a"})
	d.drain(ctx)

	// A reminder becomes due, then the alert is acknowledged before it goes.
	if _, err := f.dbs.Dialog.Pool.Exec(ctx, `UPDATE dialog.alerts SET next_reminder_at = now() - interval '1 minute'`); err != nil {
		t.Fatalf("make reminder due: %v", err)
	}
	if err := f.mgr.sendDueReminders(ctx); err != nil {
		t.Fatalf("reminders: %v", err)
	}
	if n := countDeliveries(t, f, db.DeliveryReminder); n != 1 {
		t.Fatalf("reminder deliveries = %d, want 1", n)
	}
	var next time.Time
	_ = f.dbs.Dialog.Pool.QueryRow(ctx, `SELECT next_reminder_at FROM dialog.alerts LIMIT 1`).Scan(&next)
	if time.Until(next) < 50*time.Minute {
		t.Fatalf("next reminder %v, want about an hour ahead", next)
	}
	if _, err := f.dbs.Dialog.Pool.Exec(ctx, `UPDATE dialog.alerts SET acknowledged = true, acknowledged_at = now()`); err != nil {
		t.Fatalf("ack: %v", err)
	}
	d.drain(ctx)
	if status, _, reason := deliveryStatus(t, f, db.DeliveryReminder); status != db.DeliverySkipped || reason != "alert was acknowledged" {
		t.Fatalf("reminder after ack: %s %q", status, reason)
	}

	// A disabled channel skips instead of failing forever.
	ch.Enabled = false
	if _, err := f.dbs.Muvon.UpdateAlertChannel(ctx, ch); err != nil {
		t.Fatalf("disable channel: %v", err)
	}
	if err := pgx.BeginFunc(ctx, f.dbs.Dialog.Pool, func(tx pgx.Tx) error {
		return db.QueueAlertDeliveries(ctx, tx, []string{"00000000-0000-0000-0000-000000000000"}, []alertrules.Channel{ch}, db.DeliveryTest, "info")
	}); err != nil {
		t.Fatalf("queue: %v", err)
	}
	_ = f.store.Load(ctx)
	d.drain(ctx)
	if status, _, reason := deliveryStatus(t, f, db.DeliveryTest); status != db.DeliverySkipped || reason != "channel is disabled" {
		t.Fatalf("delivery to disabled channel: %s %q", status, reason)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("sent %d messages, want only the first opening", len(sender.sent))
	}
}

func TestLegacyAlertingSettingsBecomeChannels(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for key, value := range map[string]string{
		"alerting_enabled":          `true`,
		"alerting_slack_webhook":    `"https://hooks.example.com/services/legacy"`,
		"alerting_smtp_to":          `"a@example.com, b@example.com"`,
		"alerting_cooldown_seconds": `300`,
	} {
		if err := f.dbs.Muvon.SetSetting(ctx, key, json.RawMessage(value)); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
	}

	migrated, err := f.dbs.Muvon.MigrateLegacyAlertingSettings(ctx, f.box.Encrypt)
	if err != nil || !migrated {
		t.Fatalf("migrate = %v, %v", migrated, err)
	}
	if err := f.store.Load(ctx); err != nil {
		t.Fatalf("load: %v", err)
	}
	snap := f.store.Get()
	if len(snap.Channels) != 2 {
		t.Fatalf("channels = %d, want slack and email", len(snap.Channels))
	}
	for _, c := range snap.Channels {
		if c.Kind == alertrules.ChannelSlack && c.SlackWebhook != "https://hooks.example.com/services/legacy" {
			t.Fatalf("webhook did not survive encryption: %q", c.SlackWebhook)
		}
		if c.Kind == alertrules.ChannelEmail && len(c.EmailTo) != 2 {
			t.Fatalf("recipients = %v", c.EmailTo)
		}
	}
	var stored string
	_ = f.dbs.Muvon.Pool.QueryRow(ctx, `SELECT slack_webhook FROM muvon.alert_channels WHERE kind = 'slack'`).Scan(&stored)
	if !secret.IsEncrypted(stored) {
		t.Fatal("webhook stored in plaintext")
	}
	rule := snap.Builtins[alertrules.BuiltinAuthBruteForce]
	if rule.Delivery != alertrules.DeliveryInstant || len(snap.ChannelIDsFor(rule)) != 2 {
		t.Fatalf("builtin routing = %s %v, want instant to both channels", rule.Delivery, rule.ChannelIDs)
	}
	settings, _ := f.dbs.Muvon.GetAllSettings(ctx)
	for _, k := range legacyKeys() {
		if _, ok := settings[k]; ok {
			t.Fatalf("legacy key %s still present", k)
		}
	}
	if again, err := f.dbs.Muvon.MigrateLegacyAlertingSettings(ctx, f.box.Encrypt); err != nil || again {
		t.Fatalf("second run = %v, %v; want a no-op", again, err)
	}
}

func legacyKeys() []string {
	return []string{"alerting_enabled", "alerting_slack_webhook", "alerting_smtp_to", "alerting_cooldown_seconds"}
}

func TestSyncBuiltinAlertRulesKeepsOperatorRouting(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	ch := f.slackChannel(t, "ops")
	f.routeBuiltin(t, alertrules.BuiltinTrafficAnomaly, alertrules.DeliveryDigest, 15, ch.ID)

	added, err := f.dbs.Muvon.SyncBuiltinAlertRules(ctx, alertrules.BuiltinRules())
	if err != nil || added != 0 {
		t.Fatalf("resync added %d, %v; want 0", added, err)
	}
	_ = f.store.Load(ctx)
	rule := f.store.Get().Builtins[alertrules.BuiltinTrafficAnomaly]
	if rule.Delivery != alertrules.DeliveryDigest || rule.RemindMinutes != 15 || len(rule.ChannelIDs) != 1 {
		t.Fatalf("routing after resync = %+v", rule)
	}
	if len(f.store.Get().Builtins) != len(alertrules.BuiltinRules()) {
		t.Fatalf("builtins = %d, want %d", len(f.store.Get().Builtins), len(alertrules.BuiltinRules()))
	}
}

func TestPurgeKeepsOpenAlerts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	openRes := raise(t, f, db.AlertEvent{Rule: "event", Severity: "critical", Title: "open", Fingerprint: "fp:open"})
	oldRes := raise(t, f, db.AlertEvent{Rule: "event", Severity: "warning", Title: "old", Fingerprint: "fp:old"})
	if _, err := f.dbs.Dialog.Pool.Exec(ctx, `
		UPDATE dialog.alerts SET acknowledged = true, acknowledged_at = now() - interval '40 days' WHERE id = $1::uuid`, oldRes.AlertID); err != nil {
		t.Fatalf("age: %v", err)
	}
	if _, err := f.dbs.Dialog.Pool.Exec(ctx, `UPDATE dialog.alerts SET first_seen_at = now() - interval '400 days' WHERE id = $1::uuid`, openRes.AlertID); err != nil {
		t.Fatalf("age open: %v", err)
	}

	purged, _, err := f.dbs.Dialog.PurgeAcknowledgedAlerts(ctx, time.Now().AddDate(0, 0, -30))
	if err != nil || purged != 1 {
		t.Fatalf("purged %d, %v; want 1", purged, err)
	}
	if _, err := f.dbs.Dialog.GetAlert(ctx, openRes.AlertID); err != nil {
		t.Fatalf("open alert purged: %v", err)
	}
}
