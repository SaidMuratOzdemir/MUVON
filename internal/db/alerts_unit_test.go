package db

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"muvon/internal/alertrules"
)

func TestCapEvidenceKeepsFirstAndLatest(t *testing.T) {
	var existing []AlertEvidence
	for i := 0; i < alertEvidenceMax; i++ {
		existing = append(existing, AlertEvidence{LogID: fmt.Sprint(i)})
	}
	got := capEvidence(existing, []AlertEvidence{{LogID: "new"}})
	if len(got) != alertEvidenceMax {
		t.Fatalf("len = %d, want %d", len(got), alertEvidenceMax)
	}
	for i := 0; i < alertEvidenceFirst; i++ {
		if got[i].LogID != fmt.Sprint(i) {
			t.Fatalf("position %d = %s, want the line that opened the alert", i, got[i].LogID)
		}
	}
	if got[len(got)-1].LogID != "new" {
		t.Fatalf("last = %s, want the newest line", got[len(got)-1].LogID)
	}
	// The input slice must not be modified by the trim.
	if existing[alertEvidenceFirst].LogID != fmt.Sprint(alertEvidenceFirst) {
		t.Fatal("capEvidence modified its input")
	}
}

func TestReminderAt(t *testing.T) {
	at := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	ev := AlertEvent{At: at, RemindAfter: 4 * time.Hour, Delivery: alertrules.DeliveryInstant}
	existing := at.Add(time.Hour)

	if got := reminderAt(ev, alertrules.SeverityWarning, nil, true); got != nil {
		t.Errorf("warning scheduled a reminder at %v", got)
	}
	if got := reminderAt(ev, alertrules.SeverityCritical, nil, true); got == nil || !got.Equal(at.Add(4*time.Hour)) {
		t.Errorf("new critical reminder = %v, want %v", got, at.Add(4*time.Hour))
	}
	if got := reminderAt(ev, alertrules.SeverityCritical, &existing, false); got == nil || !got.Equal(existing) {
		t.Errorf("repeat of a critical alert moved the reminder to %v", got)
	}
	digest := ev
	digest.Delivery = alertrules.DeliveryDigest
	if got := reminderAt(digest, alertrules.SeverityCritical, nil, true); got != nil {
		t.Errorf("digest rule scheduled a reminder at %v", got)
	}
	test := ev
	test.IsTest = true
	if got := reminderAt(test, alertrules.SeverityCritical, nil, true); got != nil {
		t.Errorf("test alert scheduled a reminder at %v", got)
	}
}

// Existing alerts were never routed; the rebuild must bring them over closed.
func TestRebuildAlertsMigrationClosesLegacyRows(t *testing.T) {
	var sql string
	for _, m := range migrations {
		if m.name == "rebuild_alerts_as_incidents" {
			sql = m.sql
		}
	}
	if sql == "" {
		t.Fatal("rebuild_alerts_as_incidents migration missing")
	}
	for _, must := range []string{
		"RENAME TO alerts_legacy",
		"TRUE, COALESCE(acknowledged_at, now()), COALESCE(acknowledged_by, 'system:migration')",
		"CREATE UNIQUE INDEX idx_alert_open_fingerprint ON alerts (fingerprint) WHERE NOT acknowledged",
		"DROP TABLE alerts_legacy",
	} {
		if !strings.Contains(sql, must) {
			t.Errorf("migration lacks %q", must)
		}
	}
	if strings.Contains(sql, "create_hypertable") {
		t.Error("alerts must not become a hypertable again: open alerts would be dropped by retention")
	}
}
