package proxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

var (
	cfTrustSecret atomic.Pointer[string]
	cfTrustHeader atomic.Pointer[string]
)

// defaultCFTrustHeader is the header a Cloudflare Transform Rule injects when
// the operator has not named one explicitly.
const defaultCFTrustHeader = "X-Muvon-CF-Key"

// cfTrustHeaderName returns the header carrying the Cloudflare shared secret.
// Exposed so the request logger can keep that value out of stored logs: it is a
// credential, and anyone who reads it back out of the log store could forge
// CF-Connecting-IP.
func cfTrustHeaderName() string {
	if hp := cfTrustHeader.Load(); hp != nil && *hp != "" {
		return *hp
	}
	return defaultCFTrustHeader
}

// SetCloudflareTrust configures the shared-secret gate for honouring
// CF-Connecting-IP. Cloudflare's egress IPs are SHARED across every Cloudflare
// account, so peer∈CF-range alone does NOT prove a request came through the
// operator's own zone — an attacker can route through their own Cloudflare zone
// pointed at the origin and forge CF-Connecting-IP. We therefore trust
// CF-Connecting-IP only when the request also carries a secret header that the
// operator injects via a Cloudflare Transform Rule on their own zone (a value an
// attacker's zone cannot know). Empty secret = Cloudflare client-IP trust
// DISABLED (safe default).
func SetCloudflareTrust(header, secret string) {
	if header == "" {
		header = "X-Muvon-CF-Key"
	}
	cfTrustHeader.Store(&header)
	cfTrustSecret.Store(&secret)
}

// cloudflareTrustedRequest reports whether the request carries the operator's
// configured Cloudflare shared secret. Disabled (false) when no secret is set.
// CloudflareLocation returns the visitor's country and city as reported by
// Cloudflare, or empty strings when the request did not arrive through the
// operator's own Cloudflare zone.
//
// The gate is the same one that decides whether CF-Connecting-IP may set the
// client IP: the direct peer has to be a Cloudflare edge AND the request has to
// carry the operator's shared secret. Cloudflare's egress addresses are shared
// across every account, and any client can send a CF-IPCountry header, so
// without that check a visitor could pick the country attributed to them.
//
// The values come from Cloudflare's "Add visitor location headers" managed
// transform. When it is off the headers are simply absent and the log entry
// carries no location, which is the same outcome as a host that is not behind
// Cloudflare at all.
func CloudflareLocation(r *http.Request) (country, city string) {
	if !isCloudflareIP(peerHost(r)) || !cloudflareTrustedRequest(r) {
		return "", ""
	}
	country = strings.TrimSpace(r.Header.Get("CF-IPCountry"))
	// XX marks an address Cloudflare could not place, and T1 marks Tor exits.
	// Neither is a country, so they are dropped rather than stored as one.
	if country == "XX" || country == "T1" {
		country = ""
	}
	return country, strings.TrimSpace(r.Header.Get("CF-IPCity"))
}

func cloudflareTrustedRequest(r *http.Request) bool {
	sp := cfTrustSecret.Load()
	if sp == nil || *sp == "" {
		return false
	}
	header := "X-Muvon-CF-Key"
	if hp := cfTrustHeader.Load(); hp != nil && *hp != "" {
		header = *hp
	}
	got := r.Header.Get(header)
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(*sp)) == 1
}

// cloudflareSeedCIDRs is the bundled Cloudflare edge range set used as a seed.
// It is auto-refreshed at runtime from cloudflare.com/ips-{v4,v6}, so the
// operator never maintains this list. The seed only guarantees correct
// behaviour before the first successful sync and if cloudflare.com is
// unreachable at boot.
var cloudflareSeedCIDRs = []string{
	// IPv4 — https://www.cloudflare.com/ips-v4
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	// IPv6 — https://www.cloudflare.com/ips-v6
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

// cfNetworks holds the active Cloudflare range set. Swapped atomically by the
// sync goroutine; read on every request via isCloudflareIP.
var cfNetworks atomic.Pointer[[]*net.IPNet]

func init() {
	cfNetworks.Store(parseCIDRList(cloudflareSeedCIDRs))
}

func parseCIDRList(cidrs []string) *[]*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil && n != nil {
			out = append(out, n)
		}
	}
	return &out
}

// isCloudflareIP reports whether host (an IP string, no port) falls within a
// known Cloudflare edge range.
func isCloudflareIP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	nets := cfNetworks.Load()
	if nets == nil {
		return false
	}
	for _, n := range *nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// StartCloudflareSync keeps the Cloudflare edge range set fresh by fetching the
// official published lists, then refreshing every 12h. Safe and cheap to run on
// both central MUVON and edge agents. On fetch failure the previously loaded set
// is kept (the bundled seed at minimum), so a transient network blip never
// disables Cloudflare detection. Cancel via ctx.
func StartCloudflareSync(ctx context.Context, client *http.Client) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	refresh := func() {
		v4, err4 := fetchCIDRs(ctx, client, "https://www.cloudflare.com/ips-v4")
		v6, err6 := fetchCIDRs(ctx, client, "https://www.cloudflare.com/ips-v6")
		merged := append(append([]string{}, v4...), v6...)
		if len(merged) == 0 {
			slog.Warn("cloudflare ip sync failed, keeping current set", "err_v4", err4, "err_v6", err6)
			return
		}
		cfNetworks.Store(parseCIDRList(merged))
		slog.Info("cloudflare ip ranges synced", "ranges", len(merged))
	}
	refresh()
	go func() {
		t := time.NewTicker(12 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				refresh()
			}
		}
	}()
}

func fetchCIDRs(ctx context.Context, client *http.Client, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	var out []string
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(line); err == nil {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}
