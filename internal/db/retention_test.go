package db

import (
	"strings"
	"testing"
)

func TestPlanRetentionNoOpWhenAlreadyEnforced(t *testing.T) {
	current := []RetentionPolicy{
		{Table: "http_logs", JobID: 1000, Days: 30, HasPolicy: true},
		{Table: "alerts", JobID: 1004, Days: 30, HasPolicy: true},
	}
	if got := planRetention(current, 30); len(got) != 0 {
		t.Fatalf("expected no actions, got %+v", got)
	}
}

func TestPlanRetentionAltersDrift(t *testing.T) {
	current := []RetentionPolicy{
		{Table: "http_logs", JobID: 1000, Days: 30, HasPolicy: true},
		{Table: "alerts", JobID: 1004, Days: 90, HasPolicy: true},
	}
	got := planRetention(current, 90)
	if len(got) != 1 {
		t.Fatalf("expected 1 action, got %+v", got)
	}
	if got[0].Table != "http_logs" || got[0].Verb != retentionAlter || got[0].JobID != 1000 || got[0].Days != 90 {
		t.Fatalf("unexpected action: %+v", got[0])
	}
}

func TestPlanRetentionAddsMissingPolicy(t *testing.T) {
	current := []RetentionPolicy{
		{Table: "client_events", HasPolicy: false},
	}
	got := planRetention(current, 45)
	if len(got) != 1 || got[0].Verb != retentionAdd || got[0].Days != 45 {
		t.Fatalf("expected one add action, got %+v", got)
	}
}

// Zero is the documented "keep forever" value, so it must remove the policy
// rather than be read as an interval of zero days, which would drop every
// chunk on the next run.
func TestPlanRetentionZeroRemovesPolicy(t *testing.T) {
	current := []RetentionPolicy{
		{Table: "http_logs", JobID: 1000, Days: 30, HasPolicy: true},
		{Table: "client_events", HasPolicy: false},
	}
	got := planRetention(current, 0)
	if len(got) != 1 {
		t.Fatalf("expected 1 action, got %+v", got)
	}
	if got[0].Verb != retentionRemove || got[0].JobID != 1000 {
		t.Fatalf("unexpected action: %+v", got[0])
	}
}

// The reconciler owns every hypertable that carries log data. A new one
// added later without being listed here would keep the migration default
// forever and quietly ignore the operator's setting.
func TestRetentionTablesCoverEveryLogHypertable(t *testing.T) {
	listed := map[string]bool{}
	for _, tbl := range RetentionTables {
		listed[tbl] = true
	}
	for _, m := range migrations {
		if m.product != "dialog" {
			continue
		}
		for _, line := range strings.Split(m.sql, "\n") {
			const marker = "add_retention_policy('"
			i := strings.Index(line, marker)
			if i < 0 {
				continue
			}
			rest := line[i+len(marker):]
			end := strings.Index(rest, "'")
			if end < 0 {
				continue
			}
			if tbl := rest[:end]; !listed[tbl] {
				t.Fatalf("hypertable %q has a retention policy in migrations but is missing from RetentionTables", tbl)
			}
		}
	}
}

// The stray-key migration must copy before it deletes, otherwise the
// operator's ACME address is dropped instead of moved.
func TestStraySettingsMigrationCopiesBeforeDelete(t *testing.T) {
	var sql string
	for _, m := range migrations {
		if m.name == "migrate_stray_settings_keys" {
			sql = m.sql
			break
		}
	}
	if sql == "" {
		t.Fatal("migrate_stray_settings_keys migration not found")
	}
	del := strings.Index(sql, "DELETE FROM settings")
	if del < 0 {
		t.Fatal("migration does not delete the stray keys")
	}
	for _, key := range []string{"acme_email", "acme_staging", "log_retention_days"} {
		copyAt := strings.Index(sql, "src.key = '"+key+"'")
		if copyAt < 0 {
			t.Fatalf("no copy step for %s", key)
		}
		if copyAt > del {
			t.Fatalf("copy step for %s runs after the delete", key)
		}
	}
	// Shrinking retention on deploy would delete log data, so the carry-over
	// is only allowed to raise the window.
	if !strings.Contains(sql, "(src.value #>> '{}')::int > (dst.value #>> '{}')::int") {
		t.Fatal("log_retention_days carry-over must only raise retention_days")
	}
}
