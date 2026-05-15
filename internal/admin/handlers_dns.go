package admin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"muvon/internal/db"
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
	expected, err := s.expectedHostIPs(r.Context(), host)
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

// expectedHostIPs returns the IPs DNS for this specific host should point
// at. The list is exactly one element for any normal binding: a host
// bound to central → centralPublicIP, a host bound to an edge agent →
// that agent's self-reported public_ip (with last_remote_addr as a legacy
// fallback for pre-v0.1.13 agents).
//
// No public/private filtering — internal-only topologies (Hetzner
// private network as the only path) are legitimate and the operator's
// choice.
func (s *Server) expectedHostIPs(ctx context.Context, host db.Host) ([]string, error) {
	switch host.TargetKind {
	case "central":
		ip := strings.TrimSpace(s.centralPublicIP)
		if ip == "" {
			return nil, errors.New("central public IP henüz tespit edilmedi: MUVON_PUBLIC_IP env var ile elle belirleyin")
		}
		return []string{ip}, nil
	case "agent":
		if host.TargetAgentID == nil || *host.TargetAgentID == "" {
			return nil, errors.New("host edge agent'a bağlı ama target_agent_id boş")
		}
		ag, err := s.db.GetAgent(ctx, *host.TargetAgentID)
		if err != nil {
			return nil, errors.New("hedef agent silinmiş: host'u tekrar düzenleyip yeni bir terminator seçin")
		}
		if ip := strings.TrimSpace(ag.PublicIP); ip != "" {
			return []string{ip}, nil
		}
		// Legacy fallback: agent v0.1.13'ten önce kayıt olduysa public_ip
		// rapor edilmemiş; last_remote_addr private network IP'si olabilir
		// ama yine de operatöre bir şey göster.
		if ip := stripPort(strings.TrimSpace(ag.LastRemoteAddr)); ip != "" {
			return []string{ip}, nil
		}
		return nil, errors.New("agent henüz public IP rapor etmedi: v0.1.13+ ile yeniden başlatın")
	default:
		return nil, fmt.Errorf("bilinmeyen target_kind %q", host.TargetKind)
	}
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
