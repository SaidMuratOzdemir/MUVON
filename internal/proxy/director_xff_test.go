package proxy

import (
	"net/http"
	"net/url"
	"testing"

	"muvon/internal/db"
)

// runDirector applies the Director to a synthetic request and returns it so the
// outbound forwarding headers can be inspected.
func runDirector(clientIP string, trustedHop bool, inboundXFF, inboundXRI string) *http.Request {
	target, _ := url.Parse("http://backend:8000")
	req, _ := http.NewRequest(http.MethodGet, "http://panel.example.com/api/x", nil)
	req.Host = "panel.example.com"
	if inboundXFF != "" {
		req.Header.Set("X-Forwarded-For", inboundXFF)
	}
	if inboundXRI != "" {
		req.Header.Set("X-Real-IP", inboundXRI)
	}
	Director(target, "", db.Route{}, clientIP, trustedHop)(req)
	return req
}

// Untrusted direct peer (a normal external client): a spoofed inbound
// X-Forwarded-For / X-Real-IP must never reach the backend. The outbound
// headers must carry only the resolved clientIP.
func TestDirectorXFF_UntrustedPeerDropsSpoof(t *testing.T) {
	req := runDirector("203.0.113.7", false, "1.2.3.4", "9.9.9.9")
	if got := req.Header.Get("X-Forwarded-For"); got != "203.0.113.7" {
		t.Fatalf("untrusted XFF = %q, want %q (spoofed prior must be dropped)", got, "203.0.113.7")
	}
	if got := req.Header.Get("X-Real-IP"); got != "203.0.113.7" {
		t.Fatalf("untrusted X-Real-IP = %q, want %q (inbound spoof must be overwritten)", got, "203.0.113.7")
	}
}

// Trusted upstream proxy (e.g. a real CDN in front): the inbound chain is
// legitimate and must be preserved, with the resolved clientIP appended.
func TestDirectorXFF_TrustedPeerPreservesChain(t *testing.T) {
	req := runDirector("10.0.0.2", true, "203.0.113.7", "")
	if got := req.Header.Get("X-Forwarded-For"); got != "203.0.113.7, 10.0.0.2" {
		t.Fatalf("trusted XFF = %q, want %q (chain preserved + clientIP appended)", got, "203.0.113.7, 10.0.0.2")
	}
}

// No inbound XFF: outbound is just the clientIP regardless of trust.
func TestDirectorXFF_NoInbound(t *testing.T) {
	req := runDirector("203.0.113.7", false, "", "")
	if got := req.Header.Get("X-Forwarded-For"); got != "203.0.113.7" {
		t.Fatalf("no-inbound XFF = %q, want %q", got, "203.0.113.7")
	}
}
