package db

import (
	"context"
	"os"
	"testing"
	"time"
)

// Retention is enforced by TimescaleDB's job catalog, not by our own SQL, so
// the only way to know the statements are right is to run them against a real
// Timescale. The test is skipped unless MUVON_TEST_PG_DSN points at a
// throwaway database; it creates its own hypertables and drops them after.
//
//	docker run -d --name muvon-retention-test -e POSTGRES_PASSWORD=test \
//	  -e POSTGRES_DB=muvon -e POSTGRES_USER=muvon -p 55432:5432 \
//	  timescale/timescaledb:latest-pg17
//	MUVON_TEST_PG_DSN='postgres://muvon:test@localhost:55432/muvon?sslmode=disable' \
//	  go test ./internal/db -run TestApplyRetentionAgainstTimescale -v
func TestApplyRetentionAgainstTimescale(t *testing.T) {
	dsn := os.Getenv("MUVON_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("MUVON_TEST_PG_DSN not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	database, err := New(ctx, dsn, RetentionSchema)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer database.Close()

	if _, err := database.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS timescaledb`); err != nil {
		t.Fatalf("create extension: %v", err)
	}

	// Build the same shape the migrations produce: a hypertable per retention
	// table, each starting at the 30 day default.
	for _, tbl := range RetentionTables {
		q := `CREATE TABLE IF NOT EXISTS ` + RetentionSchema + `.` + tbl + ` (timestamp TIMESTAMPTZ NOT NULL, v INT)`
		if _, err := database.Pool.Exec(ctx, q); err != nil {
			t.Fatalf("create %s: %v", tbl, err)
		}
		if _, err := database.Pool.Exec(ctx,
			`SELECT create_hypertable($1::regclass, by_range('timestamp', INTERVAL '1 day'), if_not_exists => true)`,
			RetentionSchema+"."+tbl); err != nil {
			t.Fatalf("hypertable %s: %v", tbl, err)
		}
		if _, err := database.Pool.Exec(ctx,
			`SELECT add_retention_policy($1::regclass, drop_after => INTERVAL '30 days', if_not_exists => true)`,
			RetentionSchema+"."+tbl); err != nil {
			t.Fatalf("seed policy %s: %v", tbl, err)
		}
	}
	t.Cleanup(func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, tbl := range RetentionTables {
			database.Pool.Exec(cleanCtx, `DROP TABLE IF EXISTS `+RetentionSchema+`.`+tbl+` CASCADE`)
		}
	})

	assertAll := func(want int, wantPolicy bool) {
		t.Helper()
		got, err := database.GetRetentionPolicies(ctx)
		if err != nil {
			t.Fatalf("read policies: %v", err)
		}
		if len(got) != len(RetentionTables) {
			t.Fatalf("expected %d policies, got %d (%+v)", len(RetentionTables), len(got), got)
		}
		for i, p := range got {
			if p.Table != RetentionTables[i] {
				t.Fatalf("policy %d is %s, expected %s (order must be stable)", i, p.Table, RetentionTables[i])
			}
			if p.HasPolicy != wantPolicy {
				t.Fatalf("%s: has_policy=%v, want %v", p.Table, p.HasPolicy, wantPolicy)
			}
			if wantPolicy && p.Days != want {
				t.Fatalf("%s: enforcing %d days, want %d", p.Table, p.Days, want)
			}
		}
	}

	assertAll(30, true)

	// Raise the window: every table must follow, and the job ids must survive
	// so the schedule and run history are not reset.
	before, err := database.GetRetentionPolicies(ctx)
	if err != nil {
		t.Fatalf("read policies: %v", err)
	}
	changed, err := database.ApplyRetention(ctx, 90)
	if err != nil {
		t.Fatalf("apply 90: %v", err)
	}
	if len(changed) != len(RetentionTables) {
		t.Fatalf("expected all tables to change, got %v", changed)
	}
	assertAll(90, true)

	after, err := database.GetRetentionPolicies(ctx)
	if err != nil {
		t.Fatalf("read policies: %v", err)
	}
	for i := range before {
		if before[i].JobID != after[i].JobID {
			t.Fatalf("%s: job id changed %d -> %d, alter_job should preserve it",
				before[i].Table, before[i].JobID, after[i].JobID)
		}
	}

	// Reapplying the same value must be a no-op, otherwise the reconciler
	// would rewrite the catalog on every pass.
	changed, err = database.ApplyRetention(ctx, 90)
	if err != nil {
		t.Fatalf("reapply 90: %v", err)
	}
	if len(changed) != 0 {
		t.Fatalf("expected no changes on reapply, got %v", changed)
	}

	// Zero means keep forever: the policies come off entirely.
	if _, err := database.ApplyRetention(ctx, 0); err != nil {
		t.Fatalf("apply 0: %v", err)
	}
	assertAll(0, false)

	// And a policy can be installed again from nothing.
	changed, err = database.ApplyRetention(ctx, 45)
	if err != nil {
		t.Fatalf("apply 45: %v", err)
	}
	if len(changed) != len(RetentionTables) {
		t.Fatalf("expected all tables to change, got %v", changed)
	}
	assertAll(45, true)

	if _, err := database.ApplyRetention(ctx, -1); err == nil {
		t.Fatal("negative retention must be rejected")
	}
	if _, err := database.ApplyRetention(ctx, MaxRetentionDays+1); err == nil {
		t.Fatal("retention beyond the cap must be rejected")
	}
	// A rejected value must not have touched the catalog.
	assertAll(45, true)
}
