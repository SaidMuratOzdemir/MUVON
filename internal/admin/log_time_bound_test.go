package admin

import (
	"strings"
	"testing"
)

// The pipeline parses these bounds with a strict RFC3339 and discards the
// error, so anything this function lets through and the parser then rejects
// becomes a filter that silently does nothing. The panel's own
// `datetime-local` value is the case worth pinning, since it is the shape a
// browser produces without anyone typing it.
func TestValidTimeBound(t *testing.T) {
	valid := []string{
		"2026-08-23T14:30:00Z",
		"2026-08-23T14:30:00+03:00",
		"2026-08-23T14:30:00.123456789Z",
	}
	for _, v := range valid {
		if err := validTimeBound("from", v); err != nil {
			t.Errorf("validTimeBound(%q) = %v, want nil", v, err)
		}
	}

	invalid := []string{
		"2026-08-23T14:30", // what an <input type="datetime-local"> produces
		"2026-08-23",       // date only
		"1h",               // relative, which this API does not accept
		"23/08/2026 14:30", // localised
		"not-a-time",
	}
	for _, v := range invalid {
		if err := validTimeBound("from", v); err == nil {
			t.Errorf("validTimeBound(%q) = nil, want an error", v)
		}
	}
}

// The message has to name the parameter and show the value, because the
// caller's next move is fixing their own query string.
func TestValidTimeBoundErrorNamesParamAndValue(t *testing.T) {
	err := validTimeBound("to", "2026-08-23T14:30")
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"to", "2026-08-23T14:30", "RFC3339"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}
}

// The numeric filters reach SQL directly, so anything this lets through has to
// be something Postgres will accept. A negative offset is the sharp case: it is
// a syntax error there, which the caller would see as a 500 carrying a database
// message rather than a statement about their own request.
func TestValidCount(t *testing.T) {
	for _, v := range []string{"0", "1", "50", "10000"} {
		if got, err := validCount("limit", v); err != nil {
			t.Errorf("validCount(%q) rejected a usable value: %v", v, err)
		} else if got < 0 {
			t.Errorf("validCount(%q) = %d, want non-negative", v, got)
		}
	}

	for _, v := range []string{"-1", "-50", "abc", "1.5", "1e3", " 5", "", "50; DROP TABLE"} {
		if _, err := validCount("offset", v); err == nil {
			t.Errorf("validCount(%q) was accepted, want refused", v)
		}
	}

	err := validCount0Err(t, "offset", "-5")
	for _, want := range []string{"offset", "-5"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should name %q so the caller can fix the request", err, want)
		}
	}
}

func validCount0Err(t *testing.T, name, v string) error {
	t.Helper()
	_, err := validCount(name, v)
	if err == nil {
		t.Fatalf("validCount(%q, %q) should have failed", name, v)
	}
	return err
}
