package logger_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"muvon/internal/logger"
	"muvon/internal/testpg"
)

// recordingHook writes one row per line in the transaction, or fails after
// writing when told to.
type recordingHook struct {
	fail      error
	committed chan int
}

func (h *recordingHook) InTx(ctx context.Context, tx logger.HookTx, lines []logger.StoredContainerLine) error {
	for _, l := range lines {
		if _, err := tx.Exec(ctx, `INSERT INTO hook_rows (log_id) VALUES ($1)`, l.ID); err != nil {
			return err
		}
	}
	return h.fail
}

func (h *recordingHook) AfterCommit(lines []logger.StoredContainerLine) {
	if h.committed != nil {
		h.committed <- len(lines)
	}
}

func countRows(t *testing.T, dbs testpg.DBs, query string) int {
	t.Helper()
	var n int
	if err := dbs.Dialog.Pool.QueryRow(context.Background(), query).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func TestContainerPipelineCommitsLinesWithHookRows(t *testing.T) {
	dbs := testpg.Open(t)
	ctx := context.Background()
	if _, err := dbs.Dialog.Pool.Exec(ctx, `CREATE TABLE hook_rows (log_id UUID PRIMARY KEY)`); err != nil {
		t.Fatalf("create hook table: %v", err)
	}

	p := logger.NewContainerPipeline(dbs.Dialog.Pool, 1000, 2, 100, 20*time.Millisecond)
	defer p.Stop()
	hook := &recordingHook{committed: make(chan int, 10)}
	p.SetCommitHook(hook)

	batch := []logger.ContainerEntry{
		{ContainerID: "c1", ContainerName: "api", Project: "shop", Component: "api", Stream: "stdout",
			Timestamp: time.Now(), Line: `{"event.name":"ORDER_FAILED","order_id":"42"}`},
		{ContainerID: "c1", ContainerName: "api", Stream: "stderr", Timestamp: time.Now(), Line: "plain text"},
	}
	if err := p.SendBatch(ctx, batch); err != nil {
		t.Fatalf("SendBatch: %v", err)
	}

	if n := countRows(t, dbs, `SELECT count(*) FROM container_logs`); n != 2 {
		t.Fatalf("container_logs rows = %d, want 2 at acknowledgement", n)
	}
	if n := countRows(t, dbs, `SELECT count(*) FROM hook_rows h JOIN container_logs l ON l.id = h.log_id`); n != 2 {
		t.Fatalf("hook rows joined to lines = %d, want 2", n)
	}
	if n := countRows(t, dbs, `SELECT count(*) FROM container_logs WHERE attrs->>'event.name' = 'ORDER_FAILED'`); n != 1 {
		t.Fatalf("parsed event lines = %d, want 1", n)
	}
	select {
	case got := <-hook.committed:
		if got != 2 {
			t.Fatalf("AfterCommit saw %d lines, want 2", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AfterCommit was not called")
	}
}

// A consumer defect must not stop ingest: the hook's rows roll back, the lines
// stay.
func TestContainerPipelineIsolatesFailingHook(t *testing.T) {
	dbs := testpg.Open(t)
	ctx := context.Background()
	if _, err := dbs.Dialog.Pool.Exec(ctx, `CREATE TABLE hook_rows (log_id UUID PRIMARY KEY)`); err != nil {
		t.Fatalf("create hook table: %v", err)
	}

	p := logger.NewContainerPipeline(dbs.Dialog.Pool, 1000, 1, 100, 20*time.Millisecond)
	defer p.Stop()
	p.SetCommitHook(&recordingHook{fail: &pgconn.PgError{Code: "23505", Message: "duplicate"}})

	err := p.SendBatch(ctx, []logger.ContainerEntry{{ContainerID: "c1", ContainerName: "api", Stream: "stdout", Line: "x"}})
	if err != nil {
		t.Fatalf("SendBatch: %v", err)
	}
	if n := countRows(t, dbs, `SELECT count(*) FROM container_logs`); n != 1 {
		t.Fatalf("container_logs rows = %d, want 1", n)
	}
	if n := countRows(t, dbs, `SELECT count(*) FROM hook_rows`); n != 0 {
		t.Fatalf("hook rows = %d, want the failed hook rolled back", n)
	}
}

// A transient hook failure rolls the whole batch back and hands it to the
// shipper, so the lines and the hook's rows are retried together.
func TestContainerPipelineRetriesTransientHookFailure(t *testing.T) {
	dbs := testpg.Open(t)
	ctx := context.Background()
	if _, err := dbs.Dialog.Pool.Exec(ctx, `CREATE TABLE hook_rows (log_id UUID PRIMARY KEY)`); err != nil {
		t.Fatalf("create hook table: %v", err)
	}

	p := logger.NewContainerPipeline(dbs.Dialog.Pool, 1000, 1, 100, 20*time.Millisecond)
	defer p.Stop()
	p.SetCommitHook(&recordingHook{fail: &pgconn.PgError{Code: "40001", Message: "serialization failure"}})

	err := p.SendBatch(ctx, []logger.ContainerEntry{{ContainerID: "c1", ContainerName: "api", Stream: "stdout", Line: "x"}})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "40001" {
		t.Fatalf("SendBatch error = %v, want the transient hook error", err)
	}
	if n := countRows(t, dbs, `SELECT count(*) FROM container_logs`); n != 0 {
		t.Fatalf("container_logs rows = %d, want the batch rolled back", n)
	}
}
