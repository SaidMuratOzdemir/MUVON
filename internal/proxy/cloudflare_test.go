package proxy

import (
	"net/http"
	"testing"
)

func cfReq(remoteAddr string, headers map[string]string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://panel.example.com/api/x", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestIsCloudflareIP(t *testing.T) {
	// 104.16.0.0/13 is a published Cloudflare range (in the bundled seed).
	if !isCloudflareIP("104.16.5.5") {
		t.Fatal("104.16.5.5 should be detected as a Cloudflare IP")
	}
	if isCloudflareIP("203.0.113.7") {
		t.Fatal("203.0.113.7 (a normal client) must not be a Cloudflare IP")
	}
	if isCloudflareIP("172.18.0.2") {
		t.Fatal("172.18.0.2 (docker edge) must not be a Cloudflare IP")
	}
}

// Behind Cloudflare WITH the operator's shared secret: peer is a CF edge, the
// secret header matches, and CF set CF-Connecting-IP → that is the client.
func TestClientIPFor_BehindCloudflare(t *testing.T) {
	SetCloudflareTrust("", "topsecret")
	t.Cleanup(func() { SetCloudflareTrust("", "") })
	r := cfReq("104.16.5.5:443", map[string]string{
		"X-Muvon-CF-Key":   "topsecret",
		"CF-Connecting-IP": "203.0.113.7",
		"X-Forwarded-For":  "1.2.3.4, 203.0.113.7", // CF appends; leftmost spoofable — must be ignored
	})
	if got := clientIPFor(r, nil); got != "203.0.113.7" {
		t.Fatalf("behind CF: clientIPFor = %q, want %q (CF-Connecting-IP authoritative)", got, "203.0.113.7")
	}
}

// Disabled by default: no operator secret configured → CF-Connecting-IP is NOT
// trusted even from a real CF edge. This is the safe default and closes the
// shared-egress spoof (attacker routing through their own CF zone).
func TestClientIPFor_CloudflareDisabledByDefault(t *testing.T) {
	SetCloudflareTrust("", "") // explicit: disabled
	r := cfReq("104.16.5.5:443", map[string]string{
		"CF-Connecting-IP": "203.0.113.7",
	})
	if got := clientIPFor(r, nil); got != "104.16.5.5" {
		t.Fatalf("CF disabled: clientIPFor = %q, want %q (peer, CF-Connecting-IP untrusted)", got, "104.16.5.5")
	}
}

// Wrong/missing secret from a CF-range peer → not trusted (attacker's own CF
// zone hits the origin from a CF IP but cannot know the operator's secret).
func TestClientIPFor_CloudflareWrongSecret(t *testing.T) {
	SetCloudflareTrust("", "topsecret")
	t.Cleanup(func() { SetCloudflareTrust("", "") })
	r := cfReq("104.16.5.5:443", map[string]string{
		"X-Muvon-CF-Key":   "WRONG",
		"CF-Connecting-IP": "9.9.9.9",
	})
	if got := clientIPFor(r, nil); got != "104.16.5.5" {
		t.Fatalf("wrong secret: clientIPFor = %q, want %q (peer)", got, "104.16.5.5")
	}
}

// Spoof guard: a non-Cloudflare peer sending a forged CF-Connecting-IP must be
// ignored — the client is the real TCP peer.
func TestClientIPFor_SpoofedCFHeaderFromNonCFPeer(t *testing.T) {
	r := cfReq("198.51.100.9:5555", map[string]string{
		"CF-Connecting-IP": "9.9.9.9", // forged; peer is not a CF edge
	})
	if got := clientIPFor(r, nil); got != "198.51.100.9" {
		t.Fatalf("forged CF header: clientIPFor = %q, want %q (peer)", got, "198.51.100.9")
	}
}

// Grey cloud / direct: no CF, empty TrustedProxies → the peer is the client.
func TestClientIPFor_DirectClient(t *testing.T) {
	r := cfReq("203.0.113.7:6000", map[string]string{
		"X-Forwarded-For": "1.2.3.4", // client-supplied; untrusted → ignored
	})
	if got := clientIPFor(r, nil); got != "203.0.113.7" {
		t.Fatalf("direct: clientIPFor = %q, want %q", got, "203.0.113.7")
	}
}

// A validated Cloudflare edge counts as a trusted upstream even when it is not
// listed in TrustedProxies: the shared secret is what proves the hop.
func TestUpstreamTrusted_ValidatedCloudflareEdge(t *testing.T) {
	SetCloudflareTrust("", "topsecret")
	t.Cleanup(func() { SetCloudflareTrust("", "") })

	valid := cfReq("104.16.5.5:443", map[string]string{"X-Muvon-CF-Key": "topsecret"})
	if !upstreamTrusted(valid, nil) {
		t.Error("CF edge with the shared secret must count as a trusted upstream")
	}
	// CF address range alone proves nothing: those IPs are shared across all
	// Cloudflare accounts, so without the secret the hop stays untrusted.
	noSecret := cfReq("104.16.5.5:443", nil)
	if upstreamTrusted(noSecret, nil) {
		t.Error("CF edge without the shared secret must not be trusted")
	}
}

// End to end behind Cloudflare. The chain is preserved and our hop appended, so
// the audit trail stays intact; the authoritative client address rides on
// X-Real-IP.
//
// Note the leftmost chain entry here is attacker-controlled: Cloudflare appends
// the real client to whatever X-Forwarded-For the client supplied. That is
// inherent to the header and precisely why applications behind MUVON are told to
// read X-Real-IP instead of picking an end of the chain.
func TestForwarding_BehindCloudflare(t *testing.T) {
	SetCloudflareTrust("", "topsecret")
	t.Cleanup(func() { SetCloudflareTrust("", "") })

	r := cfReq("104.16.5.5:443", map[string]string{
		"X-Muvon-CF-Key":   "topsecret",
		"CF-Connecting-IP": "203.0.113.7",
		"X-Forwarded-For":  "1.2.3.4, 203.0.113.7",
	})
	ip := clientIPFor(r, nil)
	if ip != "203.0.113.7" {
		t.Fatalf("clientIPFor = %q, want the CF-Connecting-IP value", ip)
	}

	got := proxyThrough(t, r.RemoteAddr, ip, upstreamTrusted(r, nil), map[string]string{
		"X-Forwarded-For": r.Header.Get("X-Forwarded-For"),
	})

	const wantChain = "1.2.3.4, 203.0.113.7, 104.16.5.5"
	if xff := got.Get("X-Forwarded-For"); xff != wantChain {
		t.Errorf("X-Forwarded-For = %q, want %q", xff, wantChain)
	}
	if xri := got.Get("X-Real-IP"); xri != "203.0.113.7" {
		t.Errorf("X-Real-IP = %q, want %q", xri, "203.0.113.7")
	}
}

// The Cloudflare shared secret must never reach the log store: it is a
// credential, and reading it back would let someone forge CF-Connecting-IP.
func TestCaptureHeaders_DropsCloudflareSecret(t *testing.T) {
	SetCloudflareTrust("X-Custom-CF-Key", "topsecret")
	t.Cleanup(func() { SetCloudflareTrust("", "") })

	h := http.Header{}
	h.Set("X-Custom-CF-Key", "topsecret")
	h.Set("CF-Connecting-IP", "203.0.113.7")
	h.Set("User-Agent", "curl/8")

	got := captureHeaders(h)
	for k, v := range got {
		if v == "topsecret" {
			t.Fatalf("header %q leaked the shared secret into the captured set", k)
		}
	}
	if _, ok := got["X-Custom-CF-Key"]; ok {
		t.Error("configured CF secret header must be dropped")
	}
	if got["User-Agent"] != "curl/8" {
		t.Error("unrelated headers must still be captured")
	}
}

// The default header name is dropped too when the operator never named one.
func TestCaptureHeaders_DropsDefaultCloudflareSecretHeader(t *testing.T) {
	SetCloudflareTrust("", "topsecret")
	t.Cleanup(func() { SetCloudflareTrust("", "") })

	h := http.Header{}
	h.Set("X-Muvon-CF-Key", "topsecret")

	if _, ok := captureHeaders(h)["X-Muvon-CF-Key"]; ok {
		t.Error("default CF secret header must be dropped")
	}
}
