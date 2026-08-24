package grpcserver

import (
	"testing"
	"time"
)

// GetLogStats omits a zero bound from its WHERE clause, so a bound that cannot
// be read must fall back to the default window rather than become the zero
// time: that difference is a one day summary versus an aggregate over
// everything retained.
func TestBoundOrKeepsFallbackForUnusableValues(t *testing.T) {
	fallback := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"datetime-local from the panel", "2026-08-23T14:30"},
		{"date only", "2026-08-23"},
		{"relative", "1h"},
		{"garbage", "not a time"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := boundOr(tc.value, fallback); !got.Equal(fallback) {
				t.Fatalf("boundOr(%q) = %v, want the fallback %v", tc.value, got, fallback)
			}
		})
	}
}

func TestBoundOrUsesAParsableValue(t *testing.T) {
	fallback := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	want := time.Date(2026, 8, 20, 9, 30, 0, 0, time.UTC)

	got := boundOr(want.Format(time.RFC3339), fallback)
	if !got.Equal(want) {
		t.Fatalf("boundOr = %v, want %v", got, want)
	}
}
