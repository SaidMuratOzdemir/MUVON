package main

import (
	"testing"

	"muvon/internal/db"
)

func TestDesiredCompressionSplitsBodiesOut(t *testing.T) {
	want := desiredCompression(7, 30)
	if got := want[db.BodiesTable]; got != 30 {
		t.Fatalf("bodies should follow their own setting, got %d", got)
	}
	for _, table := range db.CompressionTables {
		if table == db.BodiesTable {
			continue
		}
		if got := want[table]; got != 7 {
			t.Fatalf("%s should follow the shared setting, got %d", table, got)
		}
	}
}

func TestOutOfRangeCompression(t *testing.T) {
	if got := outOfRangeCompression(desiredCompression(7, 30)); got != "" {
		t.Fatalf("valid values reported as out of range: %s", got)
	}
	if got := outOfRangeCompression(desiredCompression(7, -1)); got == "" {
		t.Fatal("a negative value must be reported")
	}
	if got := outOfRangeCompression(desiredCompression(db.MaxCompressionDays+1, 7)); got == "" {
		t.Fatal("a value past the cap must be reported")
	}
}

func TestSameCompression(t *testing.T) {
	a := desiredCompression(7, 30)
	if !sameCompression(a, desiredCompression(7, 30)) {
		t.Fatal("identical maps must compare equal")
	}
	if sameCompression(a, desiredCompression(7, 31)) {
		t.Fatal("a changed value must compare unequal")
	}
	if sameCompression(a, map[string]int{}) {
		t.Fatal("an empty map must compare unequal")
	}
}
