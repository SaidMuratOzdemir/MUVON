package alerting

import (
	"testing"
	"time"
)

func TestLastDigestInstant(t *testing.T) {
	istanbul, err := time.LoadLocation("Europe/Istanbul")
	if err != nil {
		t.Fatal(err)
	}
	// 08:30 Istanbul is before today's 09:00 digest: the last one due was
	// yesterday's.
	now := time.Date(2026, 9, 15, 5, 30, 0, 0, time.UTC)
	if got, want := lastDigestInstant(now, 9, istanbul), time.Date(2026, 9, 14, 9, 0, 0, 0, istanbul); !got.Equal(want) {
		t.Errorf("before the hour: %v, want %v", got, want)
	}
	// 09:00 exactly is due.
	now = time.Date(2026, 9, 15, 6, 0, 0, 0, time.UTC)
	if got, want := lastDigestInstant(now, 9, istanbul), time.Date(2026, 9, 15, 9, 0, 0, 0, istanbul); !got.Equal(want) {
		t.Errorf("at the hour: %v, want %v", got, want)
	}
	// Across a month boundary.
	now = time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	if got, want := lastDigestInstant(now, 9, time.UTC), time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("month boundary: %v, want %v", got, want)
	}
}
