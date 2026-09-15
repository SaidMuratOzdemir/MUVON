package logger

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// fakeContainerStore records what was written and fails on demand.
type fakeContainerStore struct {
	mu      sync.Mutex
	written []StoredContainerLine
	calls   int
	fail    func(lines []StoredContainerLine) error
	block   chan struct{}
}

func (s *fakeContainerStore) Write(ctx context.Context, lines []StoredContainerLine, _ ContainerCommitHook) error {
	if s.block != nil {
		select {
		case <-s.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.fail != nil {
		if err := s.fail(lines); err != nil {
			return err
		}
	}
	s.written = append(s.written, lines...)
	return nil
}

func (s *fakeContainerStore) lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.written))
	for _, l := range s.written {
		out = append(out, l.Entry.Line)
	}
	return out
}

func entries(lines ...string) []ContainerEntry {
	out := make([]ContainerEntry, 0, len(lines))
	for _, l := range lines {
		out = append(out, ContainerEntry{ContainerID: "c1", ContainerName: "c1", Stream: "stdout", Line: l})
	}
	return out
}

var errDataException = &pgconn.PgError{Code: "22P02", Message: "invalid input"}

// The acknowledgement is the commit: SendBatch returns only after the store
// has the lines.
func TestContainerPipelineAcknowledgesAfterWrite(t *testing.T) {
	store := &fakeContainerStore{}
	p := newContainerPipeline(store, 100, 1, 10, 10*time.Millisecond)
	defer p.Stop()

	if err := p.SendBatch(context.Background(), entries("a", "b", "c")); err != nil {
		t.Fatalf("SendBatch: %v", err)
	}
	if got := store.lines(); len(got) != 3 {
		t.Fatalf("written %v, want 3 lines before the acknowledgement", got)
	}
}

// One unstorable line must not cost its neighbours, and must not come back to
// the shipper as an error, or the batch would be resent forever.
func TestContainerPipelineIsolatesUnstorableLine(t *testing.T) {
	store := &fakeContainerStore{fail: func(lines []StoredContainerLine) error {
		for _, l := range lines {
			if l.Entry.Line == "bad" {
				return errDataException
			}
		}
		return nil
	}}
	p := newContainerPipeline(store, 100, 1, 10, 10*time.Millisecond)
	defer p.Stop()

	if err := p.SendBatch(context.Background(), entries("a", "b", "bad", "c", "d")); err != nil {
		t.Fatalf("SendBatch: %v", err)
	}
	got := store.lines()
	if len(got) != 4 {
		t.Fatalf("written %v, want the four good lines", got)
	}
	for _, l := range got {
		if l == "bad" {
			t.Fatal("the unstorable line was written")
		}
	}
	if _, dropped, _, _, _, _, _, _ := p.IngestStats(0); dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
}

// A transient failure is the shipper's to retry: the batch comes back as an
// error and nothing is written.
func TestContainerPipelineReturnsTransientFailure(t *testing.T) {
	transient := errors.New("connection reset")
	store := &fakeContainerStore{fail: func([]StoredContainerLine) error { return transient }}
	p := newContainerPipeline(store, 100, 1, 10, 10*time.Millisecond)
	defer p.Stop()

	err := p.SendBatch(context.Background(), entries("a", "b"))
	if !errors.Is(err, transient) {
		t.Fatalf("SendBatch error = %v, want the write error", err)
	}
	if store.calls != containerWriteAttempts {
		t.Fatalf("write attempts = %d, want %d", store.calls, containerWriteAttempts)
	}
	if got := store.lines(); len(got) != 0 {
		t.Fatalf("written %v, want nothing", got)
	}
}

// When the buffer is taken, a batch is refused whole before the deadline, so a
// resend cannot duplicate part of it.
func TestContainerPipelineRefusesWhenFull(t *testing.T) {
	store := &fakeContainerStore{block: make(chan struct{})}
	p := newContainerPipeline(store, 2, 1, 10, 10*time.Millisecond)
	defer p.Stop()

	first := make(chan error, 1)
	go func() { first <- p.SendBatch(context.Background(), entries("a", "b")) }()
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := p.SendBatch(ctx, entries("c"))
	if !errors.Is(err, ErrContainerPipelineFull) {
		t.Fatalf("second SendBatch error = %v, want ErrContainerPipelineFull", err)
	}

	close(store.block)
	if err := <-first; err != nil {
		t.Fatalf("first SendBatch: %v", err)
	}
	for _, l := range store.lines() {
		if l == "c" {
			t.Fatal("the refused batch was written")
		}
	}
}

// Batches that arrive while a writer lingers are committed together, and each
// caller still gets its own acknowledgement.
func TestContainerPipelineGroupsConcurrentBatches(t *testing.T) {
	store := &fakeContainerStore{}
	p := newContainerPipeline(store, 100, 1, 100, 100*time.Millisecond)
	defer p.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.SendBatch(context.Background(), entries("x", "y")); err != nil {
				t.Errorf("SendBatch: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := store.lines(); len(got) != 10 {
		t.Fatalf("written %d lines, want 10", len(got))
	}
	if store.calls >= 5 {
		t.Fatalf("store calls = %d, want the batches grouped into fewer writes", store.calls)
	}
}

// Stop settles what was admitted and refuses what comes after.
func TestContainerPipelineStopSettlesAdmittedBatches(t *testing.T) {
	store := &fakeContainerStore{}
	p := newContainerPipeline(store, 100, 1, 1000, time.Second)

	done := make(chan error, 1)
	go func() { done <- p.SendBatch(context.Background(), entries("a")) }()
	time.Sleep(50 * time.Millisecond)
	p.Stop()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("admitted batch settled with %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop returned without settling the admitted batch")
	}
	if err := p.SendBatch(context.Background(), entries("late")); !errors.Is(err, ErrContainerPipelineClosed) {
		t.Fatalf("SendBatch after Stop = %v, want ErrContainerPipelineClosed", err)
	}
}

// Retries and splits must write the same row ids, which is what makes a
// resent batch recognisable downstream.
func TestPrepareContainerLinesFixesIDsAndTimestamps(t *testing.T) {
	in := entries("a")
	in[0].Timestamp = time.Time{}
	in[0].Stream = "STDERR "
	lines := prepareContainerLines(in)
	if lines[0].ID.String() == "" || lines[0].Timestamp.IsZero() {
		t.Fatalf("line = %+v, want an id and a timestamp", lines[0])
	}
	if lines[0].Stream != "stderr" {
		t.Fatalf("stream = %q, want stderr", lines[0].Stream)
	}
}

func TestWriteErrorClassification(t *testing.T) {
	if !isPermanentWriteError(errDataException) {
		t.Error("a data exception must be permanent")
	}
	if isPermanentWriteError(&pgconn.PgError{Code: "42P01"}) {
		t.Error("an undefined table is an operational fault, not a bad row")
	}
	if isPermanentWriteError(errors.New("eof")) {
		t.Error("a plain error must not be permanent")
	}
	if !isTransientDBError(&pgconn.PgError{Code: "40001"}) {
		t.Error("a serialization failure must be transient")
	}
	if isTransientDBError(&pgconn.PgError{Code: "23505"}) {
		t.Error("a unique violation must not be transient")
	}
}
