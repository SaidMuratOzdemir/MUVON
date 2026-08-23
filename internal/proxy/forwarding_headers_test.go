package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"

	"muvon/internal/db"
)

// proxyThrough drives a real ReverseProxy and returns the headers the backend
// actually received.
//
// Asserting on the wire rather than on the hook in isolation is the point: the
// previous Director-based tests passed while production was wrong, because
// net/http/httputil appended the peer to X-Forwarded-For after the hook had run
// and nothing in the test ever saw the final header.
func proxyThrough(t *testing.T, peerAddr, clientIP string, trustedUpstream bool, inbound map[string]string) http.Header {
	t.Helper()

	var got http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	}))
	defer backend.Close()

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend url: %v", err)
	}
	rp := &httputil.ReverseProxy{
		Rewrite: Rewrite(target, "", db.Route{}, clientIP, trustedUpstream),
	}

	req := httptest.NewRequest(http.MethodGet, "http://panel.example.com/api/x", nil)
	req.RemoteAddr = peerAddr
	for k, v := range inbound {
		req.Header.Set(k, v)
	}
	rp.ServeHTTP(httptest.NewRecorder(), req)

	if got == nil {
		t.Fatal("backend was never reached")
	}
	return got
}

// A direct client is its own peer. The chain must name it exactly once: the old
// Director path emitted "IP, IP" because the hook wrote the resolved address and
// the stdlib then appended the identical peer.
func TestForwarding_DirectClientAppearsOnce(t *testing.T) {
	got := proxyThrough(t, "203.0.113.7:51000", "203.0.113.7", false, nil)

	if xff := got.Get("X-Forwarded-For"); xff != "203.0.113.7" {
		t.Errorf("X-Forwarded-For = %q, want %q (no duplicate entry)", xff, "203.0.113.7")
	}
	if xri := got.Get("X-Real-IP"); xri != "203.0.113.7" {
		t.Errorf("X-Real-IP = %q, want %q", xri, "203.0.113.7")
	}
}

// An untrusted peer's forwarding headers are client-controlled: the chain it
// offers must be discarded, and its X-Real-IP claim overwritten.
func TestForwarding_UntrustedPeerCannotSpoof(t *testing.T) {
	got := proxyThrough(t, "203.0.113.7:51000", "203.0.113.7", false, map[string]string{
		"X-Forwarded-For":   "1.2.3.4",
		"X-Real-IP":         "9.9.9.9",
		"X-Forwarded-Proto": "https",
	})

	if xff := got.Get("X-Forwarded-For"); xff != "203.0.113.7" {
		t.Errorf("X-Forwarded-For = %q, want the spoofed chain dropped", xff)
	}
	if xri := got.Get("X-Real-IP"); xri != "203.0.113.7" {
		t.Errorf("X-Real-IP = %q, want the spoofed value overwritten", xri)
	}
	if proto := got.Get("X-Forwarded-Proto"); proto != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want %q (untrusted scheme claim ignored)", proto, "http")
	}
}

// Behind a trusted upstream (a validated CDN edge) the reported chain is
// legitimate: keep it and append the hop we received from, so the backend sees
// client-then-CDN in order. X-Real-IP still names the client outright, which is
// what saves a backend from having to recognise CDN address ranges.
func TestForwarding_TrustedUpstreamPreservesChain(t *testing.T) {
	got := proxyThrough(t, "172.70.248.207:443", "203.0.113.7", true, map[string]string{
		"X-Forwarded-For": "203.0.113.7",
	})

	const wantChain = "203.0.113.7, 172.70.248.207"
	if xff := got.Get("X-Forwarded-For"); xff != wantChain {
		t.Errorf("X-Forwarded-For = %q, want %q", xff, wantChain)
	}
	if xri := got.Get("X-Real-IP"); xri != "203.0.113.7" {
		t.Errorf("X-Real-IP = %q, want the resolved client, not the CDN edge", xri)
	}
}

// A trusted upstream that reports a multi-hop chain keeps every hop, with ours
// appended last.
func TestForwarding_TrustedUpstreamMultiHop(t *testing.T) {
	got := proxyThrough(t, "10.0.0.9:443", "203.0.113.7", true, map[string]string{
		"X-Forwarded-For": "203.0.113.7, 198.51.100.4",
	})

	const wantChain = "203.0.113.7, 198.51.100.4, 10.0.0.9"
	if xff := got.Get("X-Forwarded-For"); xff != wantChain {
		t.Errorf("X-Forwarded-For = %q, want %q", xff, wantChain)
	}
}

// A trusted upstream may legitimately report that it terminated TLS.
func TestForwarding_TrustedUpstreamSchemeHonoured(t *testing.T) {
	got := proxyThrough(t, "172.70.248.207:443", "203.0.113.7", true, map[string]string{
		"X-Forwarded-Proto": "https",
	})

	if proto := got.Get("X-Forwarded-Proto"); proto != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want %q", proto, "https")
	}
}

// The host the client asked for is reported separately from the backend host.
func TestForwarding_ForwardedHostIsOriginal(t *testing.T) {
	got := proxyThrough(t, "203.0.113.7:51000", "203.0.113.7", false, nil)

	if h := got.Get("X-Forwarded-Host"); h != "panel.example.com" {
		t.Errorf("X-Forwarded-Host = %q, want %q", h, "panel.example.com")
	}
}
