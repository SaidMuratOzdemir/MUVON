package scheduler

import (
	"context"
	"testing"
	"time"

	"muvon/internal/db"
)

// fakeStore records the scheduler's decisions so a single tick can be
// asserted without a database.
type fakeStore struct {
	due      []db.ScheduledJob
	active   map[int64]bool
	enqueued []int64
	skipped  []int64
	advanced map[int64]time.Time
}

func newFakeStore(jobs ...db.ScheduledJob) *fakeStore {
	return &fakeStore{
		due:      jobs,
		active:   map[int64]bool{},
		advanced: map[int64]time.Time{},
	}
}

func (f *fakeStore) ListDueJobs(_ context.Context, _ time.Time) ([]db.ScheduledJob, error) {
	return f.due, nil
}
func (f *fakeStore) HasActiveRun(_ context.Context, jobID int64) (bool, error) {
	return f.active[jobID], nil
}
func (f *fakeStore) EnqueueJobRun(_ context.Context, jobID int64, _ string, _ time.Time, _ string) (bool, error) {
	f.enqueued = append(f.enqueued, jobID)
	return true, nil
}
func (f *fakeStore) RecordSkippedRun(_ context.Context, jobID int64, _ string, _ time.Time) error {
	f.skipped = append(f.skipped, jobID)
	return nil
}
func (f *fakeStore) AdvanceJobSchedule(_ context.Context, jobID int64, _ time.Time, nextRun time.Time) error {
	f.advanced[jobID] = nextRun
	return nil
}

func dueJob(id int64, schedule, policy string) db.ScheduledJob {
	now := time.Now().Add(-time.Minute)
	return db.ScheduledJob{
		ID:                id,
		Slug:              "job",
		Schedule:          schedule,
		Timezone:          "UTC",
		ConcurrencyPolicy: policy,
		NextRunAt:         &now,
	}
}

func TestTickEnqueuesAndAdvances(t *testing.T) {
	store := newFakeStore(dueJob(1, "*/5 * * * *", "allow"))
	s := New(store, time.Minute)
	if err := s.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.enqueued) != 1 || store.enqueued[0] != 1 {
		t.Fatalf("expected job 1 enqueued, got %v", store.enqueued)
	}
	next, ok := store.advanced[1]
	if !ok || !next.After(time.Now()) {
		t.Fatalf("expected next_run advanced into the future, got %v", next)
	}
}

func TestTickForbidSkipsWhenActive(t *testing.T) {
	store := newFakeStore(dueJob(1, "*/5 * * * *", "forbid"))
	store.active[1] = true
	s := New(store, time.Minute)
	if err := s.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.enqueued) != 0 {
		t.Fatalf("expected no enqueue while a run is active, got %v", store.enqueued)
	}
	if len(store.skipped) != 1 {
		t.Fatalf("expected a skipped run recorded, got %v", store.skipped)
	}
	if _, ok := store.advanced[1]; !ok {
		t.Fatal("expected schedule to still advance after a skip")
	}
}

func TestTickForbidRunsWhenIdle(t *testing.T) {
	store := newFakeStore(dueJob(1, "*/5 * * * *", "forbid"))
	s := New(store, time.Minute)
	if err := s.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.enqueued) != 1 {
		t.Fatalf("expected enqueue when no active run, got %v", store.enqueued)
	}
	if len(store.skipped) != 0 {
		t.Fatalf("expected no skip when idle, got %v", store.skipped)
	}
}

func TestTickBadScheduleDefersWithoutEnqueue(t *testing.T) {
	store := newFakeStore(dueJob(1, "this is not cron", "allow"))
	s := New(store, time.Minute)
	if err := s.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.enqueued) != 0 {
		t.Fatalf("bad schedule should not enqueue, got %v", store.enqueued)
	}
	next, ok := store.advanced[1]
	if !ok || !next.After(time.Now()) {
		t.Fatalf("bad schedule should still defer next_run forward, got %v", next)
	}
}
