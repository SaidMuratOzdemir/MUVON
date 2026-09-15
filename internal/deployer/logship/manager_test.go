package logship

import (
	"testing"
	"time"
)

// A spooled finished_at marker must reach dialog-siem as batch meta. Sent as
// an entry it becomes an empty container_logs row and the finish time is lost,
// which is what replay did before markers carried FinishedAt.
func TestBuildPBBatchTurnsMarkerIntoMeta(t *testing.T) {
	meta := ContainerMeta{ContainerID: "c1", ContainerName: "c1-name", HostID: "central"}
	finished := time.Date(2026, 9, 15, 9, 20, 19, 0, time.UTC)

	entries := []SpooledEntry{
		makeEntry("c1", "last line", 7),
		dimensionMarker(meta, &finished),
	}
	batch := buildPBBatch(meta, entries)

	if len(batch.Entries) != 1 {
		t.Fatalf("entries = %d, want 1 (the marker is not a line)", len(batch.Entries))
	}
	if batch.Entries[0].Line != "last line" {
		t.Errorf("entry line = %q, want %q", batch.Entries[0].Line, "last line")
	}
	if got := batch.Meta.FinishedAt; got != finished.Format(time.RFC3339) {
		t.Errorf("meta finished_at = %q, want %q", got, finished.Format(time.RFC3339))
	}
}

// A marker written by an older shipper has no FinishedAt. It still must not
// turn into a row.
func TestBuildPBBatchDropsLegacyMarker(t *testing.T) {
	meta := ContainerMeta{ContainerID: "c1"}
	legacy := SpooledEntry{ContainerID: "c1", Stream: "stdout", Seq: dimensionMarkerSeq}

	batch := buildPBBatch(meta, []SpooledEntry{legacy})
	if len(batch.Entries) != 0 {
		t.Fatalf("entries = %d, want 0", len(batch.Entries))
	}
	if batch.Meta.FinishedAt != "" {
		t.Errorf("meta finished_at = %q, want empty", batch.Meta.FinishedAt)
	}
}

// The marker survives the spool's JSON round trip with its finish time.
func TestDimensionMarkerRoundTripsThroughSpool(t *testing.T) {
	s, err := NewSpool(t.TempDir(), 1<<20, 256<<10)
	if err != nil {
		t.Fatalf("NewSpool: %v", err)
	}
	meta := ContainerMeta{ContainerID: "c1", HostID: "central"}
	finished := time.Date(2026, 9, 15, 9, 20, 19, 0, time.UTC)
	if err := s.Append("c1", []SpooledEntry{dimensionMarker(meta, &finished)}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	var got []SpooledEntry
	if _, err := s.Drain("c1", 10, func(b []SpooledEntry) error {
		got = append(got, b...)
		return nil
	}); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(got) != 1 || !got[0].isDimensionMarker() {
		t.Fatalf("drained %+v, want one marker", got)
	}
	if got[0].FinishedAt == nil || !got[0].FinishedAt.Equal(finished) {
		t.Fatalf("FinishedAt = %v, want %v", got[0].FinishedAt, finished)
	}
}
