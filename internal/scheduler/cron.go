// Package scheduler turns scheduled_jobs rows into pending
// scheduled_job_runs on a cron cadence. It runs only on the central muvon
// binary; the deployer (central or edge) is the executor. Cron parsing is
// isolated here so it can be unit-tested without a database.
package scheduler

import (
	"fmt"
	"time"

	"github.com/robfig/cron/v3"
)

// NextRun computes the next fire time strictly after `after`, interpreting
// the standard 5-field cron expression in the given IANA timezone. An empty
// timezone defaults to UTC. The returned time is in UTC so callers store a
// timezone-independent instant.
//
// We use robfig/cron only as a parser (ParseStandard + Next); the cron
// library's own scheduler/runner is never started — our DB-backed loop owns
// firing so schedules survive restarts.
func NextRun(schedule, timezone string, after time.Time) (time.Time, error) {
	if timezone == "" {
		timezone = "UTC"
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timezone %q: %w", timezone, err)
	}
	sched, err := cron.ParseStandard(schedule)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid cron schedule %q: %w", schedule, err)
	}
	return sched.Next(after.In(loc)).UTC(), nil
}

// ValidateSchedule reports whether a (schedule, timezone) pair parses. The
// admin handler calls this on create/update so a bad expression is a 400,
// never a silently dead job.
func ValidateSchedule(schedule, timezone string) error {
	_, err := NextRun(schedule, timezone, time.Now())
	return err
}
