package scheduler

import (
	"context"
	"log/slog"
	"time"

	"muvon/internal/db"
)

// store is the slice of *db.DB the scheduler touches. An interface keeps
// the tick loop testable without a live PostgreSQL.
type store interface {
	ListDueJobs(ctx context.Context, now time.Time) ([]db.ScheduledJob, error)
	HasActiveRun(ctx context.Context, jobID int64) (bool, error)
	EnqueueJobRun(ctx context.Context, jobID int64, agentID string, scheduledFor time.Time, trigger string) (bool, error)
	RecordSkippedRun(ctx context.Context, jobID int64, agentID string, scheduledFor time.Time) error
	AdvanceJobSchedule(ctx context.Context, jobID int64, lastRun, nextRun time.Time) error
}

// Scheduler enqueues due scheduled_job_runs on a fixed cadence. It is a
// central-only goroutine — the deployer (central or edge) executes the runs
// it produces.
type Scheduler struct {
	db       store
	interval time.Duration
}

// New builds a Scheduler. interval is the tick cadence (how often due jobs
// are scanned); 30s matches the agent-command sweeper. Cron granularity is
// per-minute, so a sub-minute tick just means due jobs fire promptly.
func New(database store, interval time.Duration) *Scheduler {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Scheduler{db: database, interval: interval}
}

func (s *Scheduler) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		if err := s.tick(ctx); err != nil {
			slog.Error("scheduler tick failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// tick enqueues one run per due job and advances each job's next_run_at to
// the next cron boundary after now. Crash recovery is implicit: a job whose
// next_run_at fell into the past while muvon was down fires exactly one
// catch-up run (its stale boundary) and is then realigned to the future —
// no per-missed-tick backfill, by design.
func (s *Scheduler) tick(ctx context.Context) error {
	now := time.Now()
	jobs, err := s.db.ListDueJobs(ctx, now)
	if err != nil {
		return err
	}
	for _, job := range jobs {
		scheduledFor := now
		if job.NextRunAt != nil {
			scheduledFor = *job.NextRunAt
		}

		next, nerr := NextRun(job.Schedule, job.Timezone, now)
		if nerr != nil {
			// Validated at create/update, so this is operator SQL tampering
			// or a tzdata gap. Push next_run out an hour so we don't hot-loop
			// on the same bad row every tick.
			slog.Warn("scheduler: bad schedule, deferring", "job_id", job.ID, "schedule", job.Schedule, "error", nerr)
			_ = s.db.AdvanceJobSchedule(ctx, job.ID, now, now.Add(time.Hour))
			continue
		}

		if job.ConcurrencyPolicy == "forbid" {
			active, herr := s.db.HasActiveRun(ctx, job.ID)
			if herr != nil {
				slog.Warn("scheduler: active-run check failed", "job_id", job.ID, "error", herr)
				continue
			}
			if active {
				if err := s.db.RecordSkippedRun(ctx, job.ID, job.AgentID, scheduledFor); err != nil {
					slog.Warn("scheduler: record skipped run failed", "job_id", job.ID, "error", err)
				}
				_ = s.db.AdvanceJobSchedule(ctx, job.ID, now, next)
				continue
			}
		}

		created, eerr := s.db.EnqueueJobRun(ctx, job.ID, job.AgentID, scheduledFor, "schedule")
		if eerr != nil {
			slog.Warn("scheduler: enqueue failed", "job_id", job.ID, "error", eerr)
			continue
		}
		if created {
			slog.Info("scheduled job enqueued", "job_id", job.ID, "slug", job.Slug, "scheduled_for", scheduledFor)
		}
		_ = s.db.AdvanceJobSchedule(ctx, job.ID, now, next)
	}
	return nil
}
