package db

import (
	"context"
	"fmt"
	"time"
)

// RetentionSchema is where every log hypertable lives. Retention is a diaLOG
// concern: MUVON's own tables are small and not time-partitioned.
const RetentionSchema = "dialog"

// RetentionTables are the hypertables governed by the single retention_days
// setting. Order is stable so log lines and API responses read the same way
// on every run.
var RetentionTables = []string{
	"http_logs",
	"http_log_bodies",
	"container_logs",
	"client_events",
	"alerts",
}

// MaxRetentionDays caps the knob. Ten years of request bodies is never what
// an operator meant to type, and Timescale would happily accept it.
const MaxRetentionDays = 3650

// RetentionPolicy is what Timescale actually enforces for one hypertable,
// read back from its job catalog rather than assumed from configuration.
// Days is 0 with HasPolicy false when no policy is installed at all, which
// means chunks are never dropped.
type RetentionPolicy struct {
	Table     string     `json:"table"`
	JobID     int64      `json:"job_id,omitempty"`
	Days      int        `json:"days"`
	HasPolicy bool       `json:"has_policy"`
	NextRun   *time.Time `json:"next_run,omitempty"`
}

// GetRetentionPolicies reports the installed retention policy per hypertable.
// Tables that do not exist yet (a migration not applied on this deployment)
// are simply absent from the result.
func (d *DB) GetRetentionPolicies(ctx context.Context) ([]RetentionPolicy, error) {
	const q = `
SELECT h.hypertable_name,
       COALESCE(j.job_id, 0),
       COALESCE(EXTRACT(EPOCH FROM (j.config->>'drop_after')::interval) / 86400, 0)::int,
       j.job_id IS NOT NULL,
       j.next_start
FROM timescaledb_information.hypertables h
LEFT JOIN timescaledb_information.jobs j
       ON j.hypertable_schema = h.hypertable_schema
      AND j.hypertable_name   = h.hypertable_name
      AND j.proc_name         = 'policy_retention'
WHERE h.hypertable_schema = $1
  AND h.hypertable_name = ANY($2)
ORDER BY array_position($2::text[], h.hypertable_name)`

	rows, err := d.Pool.Query(ctx, q, RetentionSchema, RetentionTables)
	if err != nil {
		return nil, fmt.Errorf("db: read retention policies: %w", err)
	}
	defer rows.Close()

	var out []RetentionPolicy
	for rows.Next() {
		var p RetentionPolicy
		if err := rows.Scan(&p.Table, &p.JobID, &p.Days, &p.HasPolicy, &p.NextRun); err != nil {
			return nil, fmt.Errorf("db: scan retention policy: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: read retention policies: %w", err)
	}
	return out, nil
}

// retentionAction is one reconciliation step. Keeping the decision separate
// from the SQL lets the policy logic be tested without a database.
type retentionAction struct {
	Table string
	JobID int64
	Verb  retentionVerb
	Days  int
}

type retentionVerb int

const (
	retentionAdd retentionVerb = iota
	retentionAlter
	retentionRemove
)

// planRetention decides what has to change so every table enforces days.
// days == 0 means "keep forever" and removes the policies.
func planRetention(current []RetentionPolicy, days int) []retentionAction {
	var actions []retentionAction
	for _, p := range current {
		switch {
		case days == 0 && p.HasPolicy:
			actions = append(actions, retentionAction{Table: p.Table, JobID: p.JobID, Verb: retentionRemove})
		case days > 0 && !p.HasPolicy:
			actions = append(actions, retentionAction{Table: p.Table, Verb: retentionAdd, Days: days})
		case days > 0 && p.Days != days:
			actions = append(actions, retentionAction{Table: p.Table, JobID: p.JobID, Verb: retentionAlter, Days: days})
		}
	}
	return actions
}

// ApplyRetention makes Timescale enforce days on every retention table and
// returns the tables whose policy actually changed, so callers can stay quiet
// in the steady state.
//
// Lowering the value deletes the chunks that fall outside the new window on
// the policy's next run, and that deletion is final: chunks are dropped, not
// archived, and no continuous aggregate keeps a summary behind. Raising it
// only affects data that has not been dropped yet.
func (d *DB) ApplyRetention(ctx context.Context, days int) ([]string, error) {
	if days < 0 {
		return nil, fmt.Errorf("db: retention days must not be negative (got %d)", days)
	}
	if days > MaxRetentionDays {
		return nil, fmt.Errorf("db: retention days %d exceeds the %d day cap", days, MaxRetentionDays)
	}

	current, err := d.GetRetentionPolicies(ctx)
	if err != nil {
		return nil, err
	}

	actions := planRetention(current, days)
	if len(actions) == 0 {
		return nil, nil
	}

	interval := fmt.Sprintf("%d days", days)
	changed := make([]string, 0, len(actions))
	for _, a := range actions {
		qualified := RetentionSchema + "." + a.Table
		var err error
		switch a.Verb {
		case retentionRemove:
			_, err = d.Pool.Exec(ctx, `SELECT remove_retention_policy($1::regclass, if_exists => true)`, qualified)
		case retentionAdd:
			_, err = d.Pool.Exec(ctx,
				`SELECT add_retention_policy($1::regclass, drop_after => $2::interval, if_not_exists => true)`,
				qualified, interval)
		case retentionAlter:
			// alter_job keeps the job id, schedule and run history; remove+add
			// would reset all three and briefly leave the table unprotected.
			// drop_created_before is dropped from the config first: Timescale
			// rejects a policy that carries both cutoff styles at once, and a
			// policy configured that way still has to end up on our window.
			_, err = d.Pool.Exec(ctx,
				`SELECT alter_job($1, config => ((SELECT config FROM timescaledb_information.jobs WHERE job_id = $1) - 'drop_created_before') || jsonb_build_object('drop_after', $2::text))`,
				a.JobID, interval)
		}
		if err != nil {
			return changed, fmt.Errorf("db: apply retention on %s: %w", qualified, err)
		}
		changed = append(changed, a.Table)
	}
	return changed, nil
}
