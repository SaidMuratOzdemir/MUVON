package db

import (
	"context"
	"testing"
	"time"
)

// migrateUntil applies migrations for d's schema up to, not including, stop.
func migrateUntil(ctx context.Context, t *testing.T, d *DB, stop string) {
	t.Helper()
	if _, err := d.Pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ DEFAULT now())`); err != nil {
		t.Fatalf("tracking table: %v", err)
	}
	for _, m := range migrations {
		if m.name == stop {
			return
		}
		if m.product != "" && m.product != d.Schema {
			continue
		}
		if _, err := d.Pool.Exec(ctx, m.sql); err != nil {
			t.Fatalf("migration %s: %v", m.name, err)
		}
		if _, err := d.Pool.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, m.name); err != nil {
			t.Fatalf("record %s: %v", m.name, err)
		}
	}
	t.Fatalf("migration %s not found", stop)
}

// The rebuild runs on installs that already hold alerts, including ones in
// compressed chunks, so it is exercised against a real hypertable with rows.
func TestRebuildAlertsMigrationAgainstTimescale(t *testing.T) {
	dsn := openTestDatabase(t, "pg_uuidv7", "timescaledb", "pg_trgm")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	d, err := New(ctx, dsn, "dialog", "muvon")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()
	migrateUntil(ctx, t, d, "rebuild_alerts_as_incidents")

	// One alert nobody acknowledged, one acknowledged by a person, and a row in
	// a compressed chunk.
	if _, err := d.Pool.Exec(ctx, `
		INSERT INTO alerts (timestamp, rule, severity, title, fingerprint, occurrences, last_seen_at, acknowledged, acknowledged_at, acknowledged_by)
		VALUES
		  (now() - interval '1 hour', 'auth_brute_force', 'critical', 'open one', 'fp:open', 3, now(), false, NULL, NULL),
		  (now() - interval '2 hours', 'path_scan', 'warning', 'acked one', 'fp:acked', 1, now(), true, now() - interval '1 hour', 'alice'),
		  (now() - interval '20 days', 'error_spike', 'critical', 'old one', 'fp:old', 1, now() - interval '20 days', false, NULL, NULL)`); err != nil {
		t.Fatalf("seed legacy alerts: %v", err)
	}
	if _, err := d.Pool.Exec(ctx, `SELECT compress_chunk(c, if_not_compressed => true) FROM show_chunks('alerts', older_than => interval '10 days') c`); err != nil {
		t.Fatalf("compress old chunk: %v", err)
	}

	if err := d.RunMigrations(ctx); err != nil {
		t.Fatalf("remaining migrations: %v", err)
	}

	var n, openCount int
	if err := d.Pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE NOT acknowledged) FROM dialog.alerts`).Scan(&n, &openCount); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 3 || openCount != 0 {
		t.Fatalf("rows = %d open = %d, want 3 rows and none open", n, openCount)
	}
	var by string
	if err := d.Pool.QueryRow(ctx, `SELECT acknowledged_by FROM dialog.alerts WHERE fingerprint = 'fp:acked'`).Scan(&by); err != nil || by != "alice" {
		t.Fatalf("acked row acknowledged_by = %q (%v), want the original alice", by, err)
	}
	if err := d.Pool.QueryRow(ctx, `SELECT acknowledged_by FROM dialog.alerts WHERE fingerprint = 'fp:open'`).Scan(&by); err != nil || by != "system:migration" {
		t.Fatalf("open row acknowledged_by = %q (%v), want system:migration", by, err)
	}
	var occ int
	if err := d.Pool.QueryRow(ctx, `SELECT occurrences FROM dialog.alerts WHERE fingerprint = 'fp:open'`).Scan(&occ); err != nil || occ != 3 {
		t.Fatalf("occurrences = %d (%v), want 3 carried over", occ, err)
	}
	var hyper int
	if err := d.Pool.QueryRow(ctx, `SELECT count(*) FROM timescaledb_information.hypertables WHERE hypertable_name IN ('alerts','alerts_legacy')`).Scan(&hyper); err != nil || hyper != 0 {
		t.Fatalf("hypertables named alerts = %d (%v), want 0", hyper, err)
	}
}
