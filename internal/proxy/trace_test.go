package proxy

import (
	"encoding/hex"
	"net/http"
	"regexp"
	"testing"

	"github.com/google/uuid"
)

var (
	hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex16 = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// validInboundTrace is a well-formed W3C traceparent (W3C spec example values).
const (
	validTraceID    = "4bf92f3577b34da6a3ce929d0e0e4736"
	validTraceparen = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
)

func reqWith(remoteAddr, traceparent string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
	r.RemoteAddr = remoteAddr
	if traceparent != "" {
		r.Header.Set("traceparent", traceparent)
	}
	return r
}

func TestTraceContext_GeneratesFromUUIDWhenNoInbound(t *testing.T) {
	u := uuid.Must(uuid.NewV7())
	traceID, spanID := traceContext(reqWith("203.0.113.9:5555", ""), u, nil)

	if want := hex.EncodeToString(u[:]); traceID != want {
		t.Errorf("trace-id = %q, want hex of request UUID %q", traceID, want)
	}
	if !hex32.MatchString(traceID) {
		t.Errorf("trace-id %q is not 32 lowercase hex", traceID)
	}
	if !hex16.MatchString(spanID) {
		t.Errorf("span-id %q is not 16 lowercase hex", spanID)
	}
}

func TestTraceContext_HonoursTrustedInbound(t *testing.T) {
	u := uuid.Must(uuid.NewV7())
	r := reqWith("10.0.0.7:4444", validTraceparen)
	traceID, _ := traceContext(r, u, []string{"10.0.0.7"})

	if traceID != validTraceID {
		t.Errorf("trace-id = %q, want continued inbound %q", traceID, validTraceID)
	}
}

func TestTraceContext_IgnoresUntrustedInbound(t *testing.T) {
	u := uuid.Must(uuid.NewV7())
	// Valid header, but the direct peer is NOT a trusted proxy → must not honour.
	r := reqWith("203.0.113.9:5555", validTraceparen)
	traceID, _ := traceContext(r, u, []string{"10.0.0.7"})

	if want := hex.EncodeToString(u[:]); traceID != want {
		t.Errorf("untrusted inbound was honoured: trace-id = %q, want derived %q", traceID, want)
	}
}

func TestTraceContext_EmptyTrustedListNeverHonours(t *testing.T) {
	u := uuid.Must(uuid.NewV7())
	r := reqWith("10.0.0.7:4444", validTraceparen)
	traceID, _ := traceContext(r, u, nil)

	if want := hex.EncodeToString(u[:]); traceID != want {
		t.Errorf("inbound honoured with empty trusted list: trace-id = %q, want derived %q", traceID, want)
	}
}

func TestTraceContext_IgnoresMalformedAndZero(t *testing.T) {
	cases := map[string]string{
		"too short trace-id": "00-abc-00f067aa0ba902b7-01",
		"non-hex":            "00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-00f067aa0ba902b7-01",
		"unsupported version": "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"all-zero trace-id":  "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"garbage":            "not-a-traceparent",
	}
	for name, tp := range cases {
		t.Run(name, func(t *testing.T) {
			u := uuid.Must(uuid.NewV7())
			r := reqWith("10.0.0.7:4444", tp)
			traceID, _ := traceContext(r, u, []string{"10.0.0.7"})
			if want := hex.EncodeToString(u[:]); traceID != want {
				t.Errorf("malformed inbound honoured: trace-id = %q, want derived %q", traceID, want)
			}
		})
	}
}

func TestTraceContext_NormalisesUppercaseInbound(t *testing.T) {
	u := uuid.Must(uuid.NewV7())
	r := reqWith("10.0.0.7:4444", "00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01")
	traceID, _ := traceContext(r, u, []string{"10.0.0.7"})

	if traceID != validTraceID {
		t.Errorf("uppercase inbound not normalised: trace-id = %q, want %q", traceID, validTraceID)
	}
}

func TestNewSpanID(t *testing.T) {
	a, b := newSpanID(), newSpanID()
	if !hex16.MatchString(a) {
		t.Errorf("span-id %q is not 16 lowercase hex", a)
	}
	if a == b {
		t.Errorf("two span-ids collided: %q", a)
	}
}

func TestDirectProxyTrusted(t *testing.T) {
	tests := []struct {
		name    string
		remote  string
		trusted []string
		want    bool
	}{
		{"empty list trusts nothing", "10.0.0.7:1", nil, false},
		{"exact ip match", "10.0.0.7:1", []string{"10.0.0.7"}, true},
		{"no match", "203.0.113.9:1", []string{"10.0.0.7"}, false},
		{"cidr match", "10.0.0.42:1", []string{"10.0.0.0/24"}, true},
		{"cidr miss", "10.0.1.42:1", []string{"10.0.0.0/24"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := directProxyTrusted(reqWith(tt.remote, ""), tt.trusted); got != tt.want {
				t.Errorf("directProxyTrusted(%q, %v) = %v, want %v", tt.remote, tt.trusted, got, tt.want)
			}
		})
	}
}
