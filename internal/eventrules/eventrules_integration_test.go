package eventrules

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"muvon/internal/alerting"
	"muvon/internal/alertrules"
	"muvon/internal/db"
	"muvon/internal/logger"
	"muvon/internal/secret"
	"muvon/internal/testpg"
)

type env struct {
	t         *testing.T
	dbs       testpg.DBs
	store     *alerting.Store
	mgr       *alerting.Manager
	eval      *Evaluator
	pipeline  *logger.ContainerPipeline
	projectID int
	channel   alertrules.Channel
	seq       int64
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	dbs := testpg.Open(t)
	box, err := secret.NewBox("test-key")
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, dbs: dbs}
	if err := dbs.Muvon.Pool.QueryRow(ctx,
		`INSERT INTO muvon.deploy_projects (slug, name) VALUES ('shop', 'Shop') RETURNING id`).Scan(&e.projectID); err != nil {
		t.Fatalf("project: %v", err)
	}
	if _, err := dbs.Muvon.Pool.Exec(ctx,
		`INSERT INTO muvon.deploy_projects (slug, name) VALUES ('other', 'Other')`); err != nil {
		t.Fatalf("project: %v", err)
	}
	enc, _ := box.Encrypt("https://hooks.example.com/services/x")
	e.channel, err = dbs.Muvon.CreateAlertChannel(ctx, alertrules.Channel{
		Name: "shop-ops", Kind: alertrules.ChannelSlack, Enabled: true, SlackWebhook: enc, DigestHour: 9, DigestTimezone: "UTC"})
	if err != nil {
		t.Fatalf("channel: %v", err)
	}
	if err := dbs.Muvon.SetProjectAlertChannels(ctx, e.projectID, []string{e.channel.ID}); err != nil {
		t.Fatalf("project channels: %v", err)
	}

	e.store = alerting.NewStore(dbs.Dialog, box)
	e.mgr = alerting.NewManager(dbs.Dialog, e.store)
	e.eval = NewEvaluator(dbs.Dialog, e.store, e.mgr)
	e.pipeline = logger.NewContainerPipeline(dbs.Dialog.Pool, 1000, 1, 100, 10*time.Millisecond)
	t.Cleanup(e.pipeline.Stop)
	e.pipeline.SetCommitHook(NewHook(e.store, nil))
	return e
}

func (e *env) rule(r alertrules.Rule) alertrules.Rule {
	e.t.Helper()
	r.Kind = alertrules.KindEvent
	r.Enabled = true
	r.ProjectID = &e.projectID
	if r.Delivery == "" {
		r.Delivery = alertrules.DeliveryInstant
	}
	if err := alertrules.ValidateEventRule(r); err != nil {
		e.t.Fatalf("invalid test rule: %v", err)
	}
	created, err := e.dbs.Muvon.CreateEventRule(context.Background(), r)
	if err != nil {
		e.t.Fatalf("create rule: %v", err)
	}
	e.reload()
	return created
}

func (e *env) reload() {
	e.t.Helper()
	if err := e.store.Load(context.Background()); err != nil {
		e.t.Fatalf("load rules: %v", err)
	}
}

// send ships lines for a container of project/component and evaluates.
func (e *env) send(project string, lines ...string) []logger.ContainerEntry {
	e.t.Helper()
	var batch []logger.ContainerEntry
	for _, l := range lines {
		e.seq++
		batch = append(batch, logger.ContainerEntry{
			ContainerID: "c-" + project, ContainerName: project + "-worker", Project: project, Component: "worker",
			Stream: "stdout", Line: l, Seq: e.seq, Timestamp: time.Now(),
		})
	}
	e.resend(batch)
	return batch
}

func (e *env) resend(batch []logger.ContainerEntry) {
	e.t.Helper()
	if err := e.pipeline.SendBatch(context.Background(), batch); err != nil {
		e.t.Fatalf("SendBatch: %v", err)
	}
	if _, err := e.eval.evaluateOnce(context.Background()); err != nil {
		e.t.Fatalf("evaluate: %v", err)
	}
}

func event(name string, fields map[string]any) string {
	m := map[string]any{alertrules.EventNameField: name, "level": "error"}
	for k, v := range fields {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func (e *env) alerts() []db.Alert {
	e.t.Helper()
	rows, _, err := e.dbs.Dialog.SearchAlerts(context.Background(), db.AlertSearchParams{Limit: 100})
	if err != nil {
		e.t.Fatalf("alerts: %v", err)
	}
	return rows
}

func (e *env) count(query string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.dbs.Dialog.Pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", query, err)
	}
	return n
}

func TestEachTierOpensAlertFromTheLine(t *testing.T) {
	e := newEnv(t)
	e.rule(alertrules.Rule{
		Name: "Payment blocked",
		Match: alertrules.Match{Any: []alertrules.MatchClause{
			{Events: []string{"PAYMENT_BLOCKED"}},
			{Events: []string{"JOB_FAILED"}, Fields: []alertrules.FieldCondition{{Key: "job_family", Op: alertrules.OpEquals, Values: []string{"payment"}}}},
		}},
		Tiers:         []alertrules.Tier{{Severity: alertrules.SeverityCritical, Trigger: alertrules.Trigger{Type: alertrules.TriggerEach}}},
		NotifyFields:  []string{"order_id"},
		RemindMinutes: 240,
	})

	batch := e.send("shop",
		event("PAYMENT_BLOCKED", map[string]any{"order_id": "A-1", "card_holder": "Jane Roe"}),
		"plain text line mentioning PAYMENT_BLOCKED",
		`{"level":"error","msg":"PAYMENT_BLOCKED without an event field"}`,
		event("JOB_FAILED", map[string]any{"job_family": "email"}),
	)
	e.send("other", event("PAYMENT_BLOCKED", map[string]any{"order_id": "B-1"}))

	alerts := e.alerts()
	if len(alerts) != 1 {
		t.Fatalf("alerts = %d, want 1", len(alerts))
	}
	a := alerts[0]
	if a.Severity != alertrules.SeverityCritical || a.Project != "shop" || a.Component != "worker" || a.Occurrences != 1 {
		t.Fatalf("alert = %+v", a)
	}
	var ev []db.AlertEvidence
	_ = json.Unmarshal(a.Evidence, &ev)
	if len(ev) != 1 || ev[0].Fields["order_id"] != "A-1" || ev[0].LogID == "" {
		t.Fatalf("evidence = %+v", ev)
	}
	if _, leaked := ev[0].Fields["card_holder"]; leaked {
		t.Fatal("a field the rule did not select reached the alert")
	}
	if n := e.count(`SELECT count(*) FROM dialog.container_logs WHERE id = $1::uuid`, ev[0].LogID); n != 1 {
		t.Fatal("evidence does not point at a stored line")
	}
	if n := e.count(`SELECT count(*) FROM dialog.alert_deliveries WHERE kind = 'opened' AND channel_id = $1::uuid`, e.channel.ID); n != 1 {
		t.Fatalf("opened deliveries to the project channel = %d, want 1", n)
	}
	if a.NextReminderAt == nil {
		t.Fatal("critical instant alert has no reminder scheduled")
	}

	// A resent batch, as after a lost acknowledgement, is not counted again.
	e.resend(batch)
	if got := e.alerts()[0].Occurrences; got != 1 {
		t.Fatalf("occurrences after a resend = %d, want 1", got)
	}
}

func TestCountTierEscalatesPerGroup(t *testing.T) {
	e := newEnv(t)
	e.rule(alertrules.Rule{
		Name:    "Job stuck",
		Match:   alertrules.Match{Any: []alertrules.MatchClause{{Events: []string{"JOB_STUCK"}}}},
		GroupBy: "job_id",
		Tiers: []alertrules.Tier{
			{Severity: alertrules.SeverityWarning, Trigger: alertrules.Trigger{Type: alertrules.TriggerEach}},
			{Severity: alertrules.SeverityCritical, Trigger: alertrules.Trigger{Type: alertrules.TriggerCount, Count: 2, WindowSeconds: 7200}},
		},
	})

	e.send("shop", event("JOB_STUCK", map[string]any{"job_id": "1"}))
	if a := e.alerts(); len(a) != 1 || a[0].Severity != alertrules.SeverityWarning || a[0].GroupKey != "job_id=1" {
		t.Fatalf("after first event: %+v", a)
	}
	e.send("shop", event("JOB_STUCK", map[string]any{"job_id": "1"}))
	e.send("shop", event("JOB_STUCK", map[string]any{"job_id": "2"}))

	bySeverity := map[string]db.Alert{}
	for _, a := range e.alerts() {
		bySeverity[a.GroupKey] = a
	}
	if got := bySeverity["job_id=1"]; got.Severity != alertrules.SeverityCritical || got.Occurrences != 2 {
		t.Fatalf("job 1 = %s x%d, want critical x2", got.Severity, got.Occurrences)
	}
	if got := bySeverity["job_id=2"]; got.Severity != alertrules.SeverityWarning {
		t.Fatalf("job 2 = %s, want its own warning", got.Severity)
	}
	if n := e.count(`SELECT count(*) FROM dialog.alert_deliveries WHERE kind = 'escalated'`); n != 1 {
		t.Fatalf("escalations = %d, want 1", n)
	}
}

func TestThresholdMustBeCrossedAgainAfterAcknowledgement(t *testing.T) {
	e := newEnv(t)
	e.rule(alertrules.Rule{
		Name:  "Timestamps lost",
		Match: alertrules.Match{Any: []alertrules.MatchClause{{Events: []string{"TIMESTAMP_LOST"}}}},
		Tiers: []alertrules.Tier{{Severity: alertrules.SeverityCritical, Trigger: alertrules.Trigger{Type: alertrules.TriggerCount, Count: 3, WindowSeconds: 3600}}},
	})

	e.send("shop", event("TIMESTAMP_LOST", nil), event("TIMESTAMP_LOST", nil))
	if a := e.alerts(); len(a) != 0 {
		t.Fatalf("alert below threshold: %+v", a)
	}
	e.send("shop", event("TIMESTAMP_LOST", nil))
	a := e.alerts()
	if len(a) != 1 || a[0].Occurrences != 3 {
		t.Fatalf("at threshold: %+v, want one alert counting all three", a)
	}
	var ev []db.AlertEvidence
	_ = json.Unmarshal(a[0].Evidence, &ev)
	if len(ev) != 3 {
		t.Fatalf("evidence = %d lines, want the three that crossed the threshold", len(ev))
	}

	if _, err := e.dbs.Dialog.AcknowledgeAlert(context.Background(), a[0].ID, "operator"); err != nil {
		t.Fatal(err)
	}
	e.send("shop", event("TIMESTAMP_LOST", nil))
	if open := e.count(`SELECT count(*) FROM dialog.alerts WHERE NOT acknowledged`); open != 0 {
		t.Fatalf("one event after acknowledgement reopened the alert (%d open)", open)
	}
	e.send("shop", event("TIMESTAMP_LOST", nil), event("TIMESTAMP_LOST", nil))
	if open := e.count(`SELECT count(*) FROM dialog.alerts WHERE NOT acknowledged`); open != 1 {
		t.Fatalf("open after a fresh crossing = %d, want 1", open)
	}
}

func TestDistinctTierCountsDifferentValues(t *testing.T) {
	e := newEnv(t)
	e.rule(alertrules.Rule{
		Name:  "Many jobs stuck",
		Match: alertrules.Match{Any: []alertrules.MatchClause{{Events: []string{"JOB_STUCK"}}}},
		Tiers: []alertrules.Tier{{Severity: alertrules.SeverityCritical, Trigger: alertrules.Trigger{Type: alertrules.TriggerDistinct, Field: "job_id", Count: 3, WindowSeconds: 900}}},
	})
	e.send("shop",
		event("JOB_STUCK", map[string]any{"job_id": "1"}),
		event("JOB_STUCK", map[string]any{"job_id": "1"}),
		event("JOB_STUCK", map[string]any{"job_id": "2"}))
	if a := e.alerts(); len(a) != 0 {
		t.Fatalf("two distinct jobs raised %+v", a)
	}
	e.send("shop", event("JOB_STUCK", map[string]any{"job_id": "3"}))
	if a := e.alerts(); len(a) != 1 || a[0].Occurrences != 4 {
		t.Fatalf("three distinct jobs: %+v, want one alert counting four events", a)
	}
}

func TestBaselineTierComparesWithHistory(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	rule := e.rule(alertrules.Rule{
		Name:     "Notification failures",
		Match:    alertrules.Match{Any: []alertrules.MatchClause{{Events: []string{"EMAIL_FAILED"}}}},
		Delivery: alertrules.DeliveryDigest,
		Tiers: []alertrules.Tier{
			{Severity: alertrules.SeverityInfo, Trigger: alertrules.Trigger{Type: alertrules.TriggerEach}},
			{Severity: alertrules.SeverityWarning, Trigger: alertrules.Trigger{Type: alertrules.TriggerBaseline, Ratio: 3, BaselineDays: 7, Count: 1}},
		},
	})
	if _, err := e.dbs.Muvon.Pool.Exec(ctx, `UPDATE muvon.alert_rules SET created_at = now() - interval '9 days' WHERE id = $1::uuid`, rule.ID); err != nil {
		t.Fatal(err)
	}
	e.reload()

	// One failure a day for the seven days before the last 24 hours: an
	// average of one. Mid-day offsets keep each inside the baseline window.
	var history []db.EventRuleHit
	for d := 2; d <= 8; d++ {
		at := time.Now().Add(-time.Duration(d)*24*time.Hour + 12*time.Hour)
		history = append(history, db.EventRuleHit{
			RuleID: rule.ID, DedupKey: fmt.Sprintf("h%d", d), OccurredAt: at,
			LogID: "0192a000-0000-7000-8000-000000000001", ContainerID: "c-shop", Project: "shop", EventName: "EMAIL_FAILED", Line: "{}",
		})
	}
	tx, err := e.dbs.Dialog.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertEventRuleHits(ctx, tx, history); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkHitsEvaluated(ctx, tx, history); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	e.send("shop", event("EMAIL_FAILED", nil), event("EMAIL_FAILED", nil), event("EMAIL_FAILED", nil))
	if a := e.alerts(); len(a) != 1 || a[0].Severity != alertrules.SeverityInfo {
		t.Fatalf("three in a day against an average of one: %+v, want info", a)
	}
	e.send("shop", event("EMAIL_FAILED", nil))
	a := e.alerts()
	if len(a) != 1 || a[0].Severity != alertrules.SeverityWarning {
		t.Fatalf("four in a day: %+v, want the anomaly tier", a)
	}
	if n := e.count(`SELECT count(*) FROM dialog.alert_deliveries`); n != 0 {
		t.Fatalf("a digest rule queued %d instant deliveries", n)
	}

	// The digest picks it up once per day.
	now := time.Now()
	if err := e.mgr.QueueDueDigests(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := e.mgr.QueueDueDigests(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM dialog.alert_deliveries WHERE kind = 'digest'`); n != 1 {
		t.Fatalf("digests = %d, want exactly one", n)
	}
}

func TestDisabledRuleRecordsNothing(t *testing.T) {
	e := newEnv(t)
	rule := e.rule(alertrules.Rule{
		Name:  "Payment blocked",
		Match: alertrules.Match{Any: []alertrules.MatchClause{{Events: []string{"PAYMENT_BLOCKED"}}}},
		Tiers: []alertrules.Tier{{Severity: alertrules.SeverityCritical, Trigger: alertrules.Trigger{Type: alertrules.TriggerEach}}},
	})
	rule.Enabled = false
	if _, err := e.dbs.Muvon.UpdateEventRule(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	e.reload()
	e.send("shop", event("PAYMENT_BLOCKED", nil))
	if n := e.count(`SELECT count(*) FROM dialog.event_rule_hits`); n != 0 {
		t.Fatalf("disabled rule recorded %d hits", n)
	}
	if a := e.alerts(); len(a) != 0 {
		t.Fatalf("disabled rule raised %+v", a)
	}
}
