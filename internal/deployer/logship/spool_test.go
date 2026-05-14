package logship

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func makeEntry(containerID, line string, seq int64) SpooledEntry {
	return SpooledEntry{
		ContainerID:   containerID,
		ContainerName: containerID + "-name",
		Project:       "test",
		Component:     "svc",
		HostID:        "central",
		Timestamp:     time.Now(),
		Stream:        "stdout",
		Line:          line,
		Seq:           seq,
	}
}

func TestSpool_AppendDrainRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSpool(dir, 1<<20, 256<<10)
	if err != nil {
		t.Fatalf("NewSpool: %v", err)
	}

	want := []SpooledEntry{
		makeEntry("c1", "alpha", 1),
		makeEntry("c1", "bravo", 2),
		makeEntry("c1", "charlie", 3),
	}
	if err := s.Append("c1", want); err != nil {
		t.Fatalf("Append: %v", err)
	}

	var got []SpooledEntry
	shipped, err := s.Drain("c1", 100, func(batch []SpooledEntry) error {
		got = append(got, batch...)
		return nil
	})
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if shipped != len(want) {
		t.Errorf("shipped = %d, want %d", shipped, len(want))
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Line != want[i].Line || got[i].Seq != want[i].Seq {
			t.Errorf("entry %d: got %+v, want %+v", i, got[i], want[i])
		}
	}

	// Second drain on the same container should yield zero — file
	// removed after successful drain.
	shipped2, err := s.Drain("c1", 100, func([]SpooledEntry) error { return nil })
	if err != nil {
		t.Fatalf("Drain (post): %v", err)
	}
	if shipped2 != 0 {
		t.Errorf("post-drain shipped = %d, want 0", shipped2)
	}
}

func TestSpool_DrainSendErrorKeepsFile(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSpool(dir, 1<<20, 256<<10)
	if err != nil {
		t.Fatalf("NewSpool: %v", err)
	}
	entries := []SpooledEntry{
		makeEntry("c1", "x", 1),
		makeEntry("c1", "y", 2),
	}
	if err := s.Append("c1", entries); err != nil {
		t.Fatalf("Append: %v", err)
	}

	sendErr := errors.New("transient")
	_, err = s.Drain("c1", 1, func([]SpooledEntry) error { return sendErr })
	if !errors.Is(err, sendErr) {
		t.Fatalf("Drain err = %v, want %v", err, sendErr)
	}

	// File should still exist for retry.
	pendings, err := s.PendingContainers()
	if err != nil {
		t.Fatalf("PendingContainers: %v", err)
	}
	if len(pendings) != 1 {
		t.Errorf("PendingContainers = %v, want exactly 1 sanitised entry", pendings)
	}
}

func TestSpool_GlobalQuotaEvictsOldestOther(t *testing.T) {
	dir := t.TempDir()
	// Tiny budget so we can force eviction with three small files.
	s, err := NewSpool(dir, 200, 100)
	if err != nil {
		t.Fatalf("NewSpool: %v", err)
	}

	// Old container c1 — oldest mtime.
	if err := s.Append("c1", []SpooledEntry{makeEntry("c1", "older-line", 1)}); err != nil {
		t.Fatalf("Append c1: %v", err)
	}
	time.Sleep(20 * time.Millisecond) // ensure mtime ordering

	// Newer c2 fills more.
	if err := s.Append("c2", []SpooledEntry{makeEntry("c2", "newer-line-1", 1)}); err != nil {
		t.Fatalf("Append c2: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	// c3 push that triggers eviction.
	bigPayload := makeEntry("c3", "this-is-a-line-that-pushes-us-over-the-quota-limit", 1)
	if err := s.Append("c3", []SpooledEntry{bigPayload}); err != nil {
		t.Fatalf("Append c3: %v", err)
	}

	// c1 should have been truncated; PendingContainers should reflect
	// only the survivors (c1's file may still exist but be empty).
	pending, _ := s.PendingContainers()
	if contains(pending, sanitisedFor(s, "c1")) {
		t.Errorf("expected c1 to have been evicted, got pending=%v", pending)
	}
	if !contains(pending, sanitisedFor(s, "c3")) {
		t.Errorf("expected c3 to be present, got pending=%v", pending)
	}
}

func TestSpool_AllContainerIDsRecoversIDs(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSpool(dir, 1<<20, 256<<10)
	if err != nil {
		t.Fatalf("NewSpool: %v", err)
	}
	// Use a container_id that contains characters that will be
	// sanitised in the filename (':', '-') — verifies AllContainerIDs
	// reads the original id from the file body, not the filename.
	id := "sha256:abc-def-ghi"
	if err := s.Append(id, []SpooledEntry{makeEntry(id, "x", 1)}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	ids, err := s.AllContainerIDs()
	if err != nil {
		t.Fatalf("AllContainerIDs: %v", err)
	}
	if len(ids) != 1 || ids[0] != id {
		t.Fatalf("AllContainerIDs = %v, want [%q]", ids, id)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func sanitisedFor(s *Spool, id string) string {
	// Mirrors Spool.containerFile sanitisation, exposed here just for
	// the test's PendingContainers comparison (PendingContainers
	// returns the sanitised stem).
	base := filepath.Base(s.containerFile(id))
	return base[:len(base)-len(".spool")]
}
