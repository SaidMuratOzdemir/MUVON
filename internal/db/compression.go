package db

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// CompressionTables are the hypertables whose compression policy is managed
// from settings. Order is stable so log lines and API responses read the same
// way on every run.
var CompressionTables = []string{
	"http_logs",
	"http_log_bodies",
	"container_logs",
	"client_events",
	"alerts",
}

// BodiesTable is called out because compressing it is the one choice with a
// visible cost at query time: the trigram indexes behind body search cannot be
// used on a compressed chunk, so the window kept uncompressed is the window
// where searching bodies stays indexed. It gets its own setting for that
// reason, not because it is special to any one deployment.
const BodiesTable = "http_log_bodies"

// MaxCompressionDays caps the knob for the same reason retention has one: a
// value this large is a typo, and Timescale would accept it.
const MaxCompressionDays = 3650

// CompressionPolicy is what Timescale enforces for one hypertable, read from
// its job catalog rather than assumed from configuration. Days is 0 with
// HasPolicy false when no policy is installed, which means new chunks stay
// uncompressed.
type CompressionPolicy struct {
	Table     string     `json:"table"`
	JobID     int64      `json:"job_id,omitempty"`
	Days      int        `json:"days"`
	HasPolicy bool       `json:"has_policy"`
	NextRun   *time.Time `json:"next_run,omitempty"`
	// Chunks and CompressedChunks let the panel say how much of a table is
	// already columnar, which is what an operator needs to read a policy
	// change: removing a policy stops future compression and leaves what is
	// already compressed exactly as it is.
	Chunks           int `json:"chunks"`
	CompressedChunks int `json:"compressed_chunks"`
}

// GetCompressionPolicies reports the installed policy per hypertable. Tables
// absent from this deployment are simply missing from the result.
func (d *DB) GetCompressionPolicies(ctx context.Context) ([]CompressionPolicy, error) {
	const q = `
SELECT h.hypertable_name,
       COALESCE(j.job_id, 0),
       COALESCE(EXTRACT(EPOCH FROM (j.config->>'compress_after')::interval) / 86400, 0)::int,
       j.job_id IS NOT NULL,
       -- Same guard as retention: an unscheduled job carries -infinity and
       -- neither infinity fits a time.Time, so both read as "no next run".
       CASE WHEN j.next_start IN ('-infinity'::timestamptz, 'infinity'::timestamptz)
            THEN NULL ELSE j.next_start END,
       COALESCE(c.total, 0),
       COALESCE(c.compressed, 0)
FROM timescaledb_information.hypertables h
LEFT JOIN timescaledb_information.jobs j
       ON j.hypertable_schema = h.hypertable_schema
      AND j.hypertable_name   = h.hypertable_name
      AND j.proc_name         = 'policy_compression'
LEFT JOIN (
       SELECT hypertable_name,
              count(*)                                  AS total,
              count(*) FILTER (WHERE is_compressed)      AS compressed
       FROM timescaledb_information.chunks
       WHERE hypertable_schema = $1
       GROUP BY hypertable_name
     ) c ON c.hypertable_name = h.hypertable_name
WHERE h.hypertable_schema = $1
  AND h.hypertable_name = ANY($2)
ORDER BY array_position($2::text[], h.hypertable_name)`

	rows, err := d.Pool.Query(ctx, q, RetentionSchema, CompressionTables)
	if err != nil {
		return nil, fmt.Errorf("db: read compression policies: %w", err)
	}
	defer rows.Close()

	var out []CompressionPolicy
	for rows.Next() {
		var p CompressionPolicy
		if err := rows.Scan(&p.Table, &p.JobID, &p.Days, &p.HasPolicy, &p.NextRun,
			&p.Chunks, &p.CompressedChunks); err != nil {
			return nil, fmt.Errorf("db: scan compression policy: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: read compression policies: %w", err)
	}
	return out, nil
}

type compressionVerb int

const (
	compressionAdd compressionVerb = iota
	compressionAlter
	compressionRemove
)

type compressionAction struct {
	Table string
	JobID int64
	Verb  compressionVerb
	Days  int
}

// planCompression decides what has to change so each table matches the days
// asked for it. A table missing from want is left alone; days == 0 removes the
// policy, which stops future compression without touching chunks already
// compressed.
func planCompression(current []CompressionPolicy, want map[string]int) []compressionAction {
	var actions []compressionAction
	for _, p := range current {
		days, ok := want[p.Table]
		if !ok {
			continue
		}
		switch {
		case days == 0 && p.HasPolicy:
			actions = append(actions, compressionAction{Table: p.Table, JobID: p.JobID, Verb: compressionRemove})
		case days > 0 && !p.HasPolicy:
			actions = append(actions, compressionAction{Table: p.Table, Verb: compressionAdd, Days: days})
		case days > 0 && p.Days != days:
			actions = append(actions, compressionAction{Table: p.Table, JobID: p.JobID, Verb: compressionAlter, Days: days})
		}
	}
	sort.Slice(actions, func(i, j int) bool { return actions[i].Table < actions[j].Table })
	return actions
}

// ApplyCompression makes Timescale enforce the requested window per table and
// returns the tables whose policy actually changed, so callers stay quiet in
// the steady state.
//
// Raising the value does not decompress anything that is already columnar: it
// only means later chunks wait longer. Lowering it compresses sooner on the
// policy's next run. Removing a policy (0) leaves existing compressed chunks
// compressed; nothing here decompresses data, because doing that to a large
// table is an operation an operator should start deliberately.
func (d *DB) ApplyCompression(ctx context.Context, want map[string]int) ([]string, error) {
	for table, days := range want {
		if days < 0 {
			return nil, fmt.Errorf("db: compression days for %s must not be negative (got %d)", table, days)
		}
		if days > MaxCompressionDays {
			return nil, fmt.Errorf("db: compression days %d for %s exceeds the %d day cap", days, table, MaxCompressionDays)
		}
	}

	current, err := d.GetCompressionPolicies(ctx)
	if err != nil {
		return nil, err
	}

	actions := planCompression(current, want)
	if len(actions) == 0 {
		return nil, nil
	}

	changed := make([]string, 0, len(actions))
	for _, a := range actions {
		qualified := RetentionSchema + "." + a.Table
		interval := fmt.Sprintf("%d days", a.Days)
		var err error
		switch a.Verb {
		case compressionRemove:
			_, err = d.Pool.Exec(ctx, `SELECT remove_compression_policy($1::regclass, if_exists => true)`, qualified)
		case compressionAdd:
			_, err = d.Pool.Exec(ctx,
				`SELECT add_compression_policy($1::regclass, compress_after => $2::interval, if_not_exists => true)`,
				qualified, interval)
		case compressionAlter:
			// alter_job keeps the job id, schedule and run history, which
			// remove plus add would all reset.
			_, err = d.Pool.Exec(ctx,
				`SELECT alter_job($1, config => (SELECT config FROM timescaledb_information.jobs WHERE job_id = $1) || jsonb_build_object('compress_after', $2::text))`,
				a.JobID, interval)
		}
		if err != nil {
			return changed, fmt.Errorf("db: apply compression on %s: %w", qualified, err)
		}
		changed = append(changed, a.Table)
	}
	return changed, nil
}
