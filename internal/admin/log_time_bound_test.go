package admin

import (
	"strings"
	"testing"
)

// The pipeline parses these bounds with a strict RFC3339 and discards the
// error, so anything this function lets through and the parser then rejects
// becomes a filter that silently does nothing. The panel's own
// `datetime-local` value is the case that used to slip through.
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
