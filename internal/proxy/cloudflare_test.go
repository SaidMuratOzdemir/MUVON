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

// End to end with the Director: behind CF, the outbound X-Forwarded-For and
// X-Real-IP must both carry only the resolved real client (CF's spoofable XFF
// chain dropped, since the CF peer is not in TrustedProxies → trustedHop=false).
func TestDirector_BehindCloudflare_CleanForward(t *testing.T) {
	SetCloudflareTrust("", "topsecret")
	t.Cleanup(func() { SetCloudflareTrust("", "") })
	r := cfReq("104.16.5.5:443", map[string]string{
		"X-Muvon-CF-Key":   "topsecret",
		"CF-Connecting-IP": "203.0.113.7",
		"X-Forwarded-For":  "1.2.3.4, 203.0.113.7",
	})
	ip := clientIPFor(r, nil)
	trustedHop := directProxyTrusted(r, nil) // false: CF peer not in (empty) TrustedProxies
	out := runDirector(ip, trustedHop, r.Header.Get("X-Forwarded-For"), r.Header.Get("CF-Connecting-IP"))
	if got := out.Header.Get("X-Forwarded-For"); got != "203.0.113.7" {
		t.Fatalf("behind CF outbound XFF = %q, want %q", got, "203.0.113.7")
	}
	if got := out.Header.Get("X-Real-IP"); got != "203.0.113.7" {
		t.Fatalf("behind CF outbound X-Real-IP = %q, want %q", got, "203.0.113.7")
	}
}
