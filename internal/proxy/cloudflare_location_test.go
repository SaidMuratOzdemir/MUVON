package proxy

import "testing"

const cfEdge = "104.16.5.5:41234"

// Location is attacker-controllable input until proven otherwise: any client
// can send a CF-IPCountry header, and Cloudflare's egress addresses are shared
// across every account. Only a request that came through the operator's own
// zone may set the country attributed to a visitor.
func TestCloudflareLocationRequiresTheSameTrustAsTheClientIP(t *testing.T) {
	SetCloudflareTrust("", "topsecret")
	t.Cleanup(func() { SetCloudflareTrust("", "") })

	loc := map[string]string{"CF-IPCountry": "TR", "CF-IPCity": "Istanbul"}

	t.Run("cloudflare edge with the secret", func(t *testing.T) {
		h := map[string]string{"X-Muvon-CF-Key": "topsecret"}
		for k, v := range loc {
			h[k] = v
		}
		country, city := CloudflareLocation(cfReq(cfEdge, h))
		if country != "TR" || city != "Istanbul" {
			t.Fatalf("got (%q, %q), want (TR, Istanbul)", country, city)
		}
	})

	t.Run("cloudflare edge without the secret", func(t *testing.T) {
		country, city := CloudflareLocation(cfReq(cfEdge, loc))
		if country != "" || city != "" {
			t.Fatalf("location accepted without the shared secret: (%q, %q)", country, city)
		}
	})

	t.Run("secret from a peer that is not a cloudflare edge", func(t *testing.T) {
		h := map[string]string{"X-Muvon-CF-Key": "topsecret"}
		for k, v := range loc {
			h[k] = v
		}
		country, city := CloudflareLocation(cfReq("203.0.113.7:5000", h))
		if country != "" || city != "" {
			t.Fatalf("location accepted from a non-Cloudflare peer: (%q, %q)", country, city)
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		h := map[string]string{"X-Muvon-CF-Key": "guess"}
		for k, v := range loc {
			h[k] = v
		}
		country, city := CloudflareLocation(cfReq(cfEdge, h))
		if country != "" || city != "" {
			t.Fatalf("location accepted with a wrong secret: (%q, %q)", country, city)
		}
	})
}

// With trust disabled nothing is location-enriched, even from a real edge.
func TestCloudflareLocationEmptyWhenTrustDisabled(t *testing.T) {
	SetCloudflareTrust("", "")
	country, city := CloudflareLocation(cfReq(cfEdge, map[string]string{
		"CF-IPCountry": "TR", "CF-IPCity": "Istanbul",
	}))
	if country != "" || city != "" {
		t.Fatalf("got (%q, %q), want empty", country, city)
	}
}

// XX is Cloudflare's "could not place this address" and T1 marks Tor exits.
// Storing either as a country would put a fake entry in the Top Countries list.
func TestCloudflareLocationDropsPlaceholderCountries(t *testing.T) {
	SetCloudflareTrust("", "topsecret")
	t.Cleanup(func() { SetCloudflareTrust("", "") })

	for _, code := range []string{"XX", "T1"} {
		t.Run(code, func(t *testing.T) {
			country, _ := CloudflareLocation(cfReq(cfEdge, map[string]string{
				"X-Muvon-CF-Key": "topsecret",
				"CF-IPCountry":   code,
			}))
			if country != "" {
				t.Fatalf("placeholder %s stored as a country", code)
			}
		})
	}
}

// A host behind Cloudflare without the visitor-location transform enabled sends
// no location headers; that must read as "unknown", not as an error.
func TestCloudflareLocationAbsentHeaders(t *testing.T) {
	SetCloudflareTrust("", "topsecret")
	t.Cleanup(func() { SetCloudflareTrust("", "") })

	country, city := CloudflareLocation(cfReq(cfEdge, map[string]string{"X-Muvon-CF-Key": "topsecret"}))
	if country != "" || city != "" {
		t.Fatalf("got (%q, %q), want empty", country, city)
	}
}

func TestCloudflareLocationTrimsWhitespace(t *testing.T) {
	SetCloudflareTrust("", "topsecret")
	t.Cleanup(func() { SetCloudflareTrust("", "") })

	country, city := CloudflareLocation(cfReq(cfEdge, map[string]string{
		"X-Muvon-CF-Key": "topsecret",
		"CF-IPCountry":   " TR ",
		"CF-IPCity":      " Muğla ",
	}))
	if country != "TR" || city != "Muğla" {
		t.Fatalf("got (%q, %q), want (TR, Muğla)", country, city)
	}
}
