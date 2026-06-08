package scheduler

import (
	"testing"
	"time"
)

func mustUTC(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ts.UTC()
}

func TestNextRun(t *testing.T) {
	base := mustUTC(t, "2026-01-15T02:47:00Z")
	cases := []struct {
		name     string
		schedule string
		tz       string
		want     string // RFC3339 UTC
	}{
		{"every 5 min", "*/5 * * * *", "UTC", "2026-01-15T02:50:00Z"},
		{"every 5 min empty tz defaults UTC", "*/5 * * * *", "", "2026-01-15T02:50:00Z"},
		{"daily 3am UTC", "0 3 * * *", "UTC", "2026-01-15T03:00:00Z"},
		// Istanbul is permanent UTC+3: 03:00 local == 00:00 UTC. Since base is
		// already 05:47 local, the next 03:00 local is the following day.
		{"daily 3am Istanbul", "0 3 * * *", "Europe/Istanbul", "2026-01-16T00:00:00Z"},
		// New York in January is UTC-5: 00:00 local == 05:00 UTC.
		{"midnight New York winter", "0 0 * * *", "America/New_York", "2026-01-15T05:00:00Z"},
		{"monthly 1st", "0 0 1 * *", "UTC", "2026-02-01T00:00:00Z"},
		{"hourly", "0 * * * *", "UTC", "2026-01-15T03:00:00Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NextRun(tc.schedule, tc.tz, base)
			if err != nil {
				t.Fatalf("NextRun error: %v", err)
			}
			want := mustUTC(t, tc.want)
			if !got.Equal(want) {
				t.Fatalf("NextRun(%q,%q) = %s, want %s", tc.schedule, tc.tz, got.Format(time.RFC3339), want.Format(time.RFC3339))
			}
		})
	}
}

func TestNextRunStrictlyAfter(t *testing.T) {
	// A run exactly on a boundary must advance to the *next* boundary, never
	// return the same instant — otherwise the scheduler would re-fire it.
	base := mustUTC(t, "2026-01-15T03:00:00Z")
	got, err := NextRun("0 3 * * *", "UTC", base)
	if err != nil {
		t.Fatal(err)
	}
	want := mustUTC(t, "2026-01-16T03:00:00Z")
	if !got.Equal(want) {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestNextRunDSTSpringForward(t *testing.T) {
	// Europe/Berlin springs forward 2026-03-29: 02:00 -> 03:00 local. A job
	// at 02:30 has no valid instant that day; the parser must not error and
	// must return a sane future time (the cron lib rolls the gap forward).
	base := mustUTC(t, "2026-03-29T00:00:00Z")
	got, err := NextRun("30 2 * * *", "Europe/Berlin", base)
	if err != nil {
		t.Fatalf("DST NextRun error: %v", err)
	}
	if !got.After(base) {
		t.Fatalf("DST NextRun not after base: %s", got)
	}
}

func TestValidateSchedule(t *testing.T) {
	if err := ValidateSchedule("*/10 * * * *", "UTC"); err != nil {
		t.Fatalf("valid schedule rejected: %v", err)
	}
	if err := ValidateSchedule("not a cron", "UTC"); err == nil {
		t.Fatal("invalid schedule accepted")
	}
	if err := ValidateSchedule("* * * * *", "Mars/Phobos"); err == nil {
		t.Fatal("invalid timezone accepted")
	}
	if err := ValidateSchedule("* * * * * *", "UTC"); err == nil {
		t.Fatal("6-field (seconds) schedule should be rejected by ParseStandard")
	}
}
