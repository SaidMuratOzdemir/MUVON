package admin

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DNS verification — answers "does the operator's domain currently
// resolve to a MUVON-reachable IP?". The operator runs this from the
// host detail dialog right after creating a host; without the badge,
// silent DNS misconfiguration is the most common "TLS issuance hangs"
// failure mode.
//
// Resolution is best-effort and cached in HTTP-response only — no DB
// row, no scheduler. If a host edge-bound, target IPs come from the
// agent's last_remote_addr; for central hosts, settings.public_ip.

type dnsStatusResponse struct {
	Domain      string   `json:"domain"`
	ResolvedIPs []string `json:"resolved_ips"`
	ExpectedIPs []string `json:"expected_ips"`
	// Status: "ok" — at least one resolved IP matches an expected one.
	//         "stale" — resolves to an IP we don't recognise (likely
	//           still pointing at the customer's old host).
	//         "unresolved" — no DNS record exists yet.
	//         "no_target" — central public IP not configured AND no
	//           agent could provide a fallback. Operator must set
	//           settings.public_ip before this check is meaningful.
	//         "error" — actual lookup failure (DNS server down, etc.).
	Status        string `json:"status"`
	Detail        string `json:"detail,omitempty"`
	CheckedAt     string `json:"checked_at"`
	ResolveTimeMs int    `json:"resolve_time_ms"`
}

func (s *Server) handleHostDNSStatus(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	host, err := s.db.GetHost(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "host not found"})
		return
	}
	expected, err := s.expectedHostIPs(r.Context())
	if err != nil {
		writeJSON(w, http.StatusOK, dnsStatusResponse{
			Domain:    host.Domain,
			Status:    "no_target",
			Detail:    err.Error(),
			CheckedAt: time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	// Wildcard hosts (*.example.com) have no canonical record — the
	// operator points individual subdomains. Report a distinct status
	// so the UI shows a different hint rather than "unresolved".
	if strings.HasPrefix(host.Domain, "*.") {
		writeJSON(w, http.StatusOK, dnsStatusResponse{
			Domain:      host.Domain,
			ExpectedIPs: expected,
			Status:      "wildcard",
			Detail:      "Wildcard host — DNS doğrulaması her alt alan adı için ayrı yapılır.",
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	start := time.Now()
	// Tight per-call timeout — the operator is staring at a spinner.
	lookupCtx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	resolver := net.Resolver{PreferGo: true}
	addrs, lookupErr := resolver.LookupHost(lookupCtx, host.Domain)
	elapsed := int(time.Since(start) / time.Millisecond)

	resp := dnsStatusResponse{
		Domain:        host.Domain,
		ExpectedIPs:   expected,
		ResolvedIPs:   addrs,
		CheckedAt:     time.Now().UTC().Format(time.RFC3339),
		ResolveTimeMs: elapsed,
	}
	if lookupErr != nil {
		var dnsErr *net.DNSError
		if errors.As(lookupErr, &dnsErr) && dnsErr.IsNotFound {
			resp.Status = "unresolved"
		} else {
			resp.Status = "error"
			resp.Detail = lookupErr.Error()
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	expectedSet := make(map[string]struct{}, len(expected))
	for _, ip := range expected {
		expectedSet[ip] = struct{}{}
	}
	matched := false
	for _, a := range addrs {
		if _, ok := expectedSet[a]; ok {
			matched = true
			break
		}
	}
	if matched {
		resp.Status = "ok"
	} else {
		resp.Status = "stale"
	}
	writeJSON(w, http.StatusOK, resp)
}

// expectedHostIPs collects every IP the system would accept as a valid
// DNS target for any host:
//   - central's own auto-detected public IP (s.centralPublicIP, set at
//     startup; empty when detection failed or was disabled);
//   - every active agent's self-reported public_ip;
//   - each agent's last_remote_addr as a fallback when public_ip is empty
//     (covers legacy agents that haven't been upgraded yet).
//
// No public/private filtering — internal-only topologies (Hetzner
// private network as the only path) are legitimate and the operator's
// choice.
func (s *Server) expectedHostIPs(ctx context.Context) ([]string, error) {
	seen := map[string]struct{}{}
	if ip := strings.TrimSpace(s.centralPublicIP); ip != "" {
		seen[ip] = struct{}{}
	}
	agents, err := s.db.ListAgents(ctx)
	if err == nil {
		for _, a := range agents {
			if ip := strings.TrimSpace(a.PublicIP); ip != "" {
				seen[ip] = struct{}{}
				continue
			}
			// Legacy fallback: agent hasn't reported public_ip yet.
			if ip := stripPort(strings.TrimSpace(a.LastRemoteAddr)); ip != "" {
				seen[ip] = struct{}{}
			}
		}
	}
	if len(seen) == 0 {
		return nil, errors.New("hiçbir hedef IP yok: agent kaydedin veya central'ı internet üzerinden erişilebilir bir public IP'ye taşıyın")
	}
	out := make([]string, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out, nil
}

// stripPort drops an optional ":port" or "[ipv6]:port" suffix from a
// remote-addr string the way Go's RemoteAddr emits it.
func stripPort(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// tlsStatusResponse summarises whether a host has a usable certificate
// right now, without exposing the cert bytes themselves.
type tlsStatusResponse struct {
	Domain string `json:"domain"`
	// Status: "valid", "expiring" (< 14 days), "expired", "missing",
	// "off" (host opted out via tls_mode), "wildcard" (host is wildcard
	// — issued per-subdomain so this top-level row has no single cert).
	Status    string `json:"status"`
	Issuer    string `json:"issuer,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	DaysLeft  int    `json:"days_left"`
	TLSMode   string `json:"tls_mode"`
}

func (s *Server) handleHostTLSStatus(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	host, err := s.db.GetHost(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "host not found"})
		return
	}
	resp := tlsStatusResponse{Domain: host.Domain, TLSMode: host.TLSMode}
	if host.TLSMode == "off" {
		resp.Status = "off"
		writeJSON(w, http.StatusOK, resp)
		return
	}
	if strings.HasPrefix(host.Domain, "*.") {
		resp.Status = "wildcard"
		writeJSON(w, http.StatusOK, resp)
		return
	}
	cert, err := s.db.GetCertByDomain(r.Context(), host.Domain)
	if err != nil {
		resp.Status = "missing"
		writeJSON(w, http.StatusOK, resp)
		return
	}
	resp.Issuer = cert.Issuer
	resp.ExpiresAt = cert.ExpiresAt.UTC().Format(time.RFC3339)
	resp.DaysLeft = int(time.Until(cert.ExpiresAt).Hours() / 24)
	switch {
	case resp.DaysLeft < 0:
		resp.Status = "expired"
	case resp.DaysLeft < 14:
		resp.Status = "expiring"
	default:
		resp.Status = "valid"
	}
	writeJSON(w, http.StatusOK, resp)
}
