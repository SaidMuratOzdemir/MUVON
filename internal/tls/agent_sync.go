package tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// AgentCertSync wires the agent's TLS path to the central server.
//
// Central is the source of truth for manual / admin-uploaded certificates;
// the agent is the source of truth for ACME-issued certificates because the
// http-01 challenge can only be answered at whichever IP the public DNS
// record points to (which is the agent). Two flows:
//
//  1. Pull: GetCertificate first asks central; if central has a cert for the
//     domain (typically a manual upload that should override autocert), it
//     wins. Pulls are cached in-memory with a TTL so we do not hit central
//     on every TLS handshake.
//
//  2. Push: a Cache wrapper around autocert.Cache calls central whenever
//     autocert finishes issuing a new cert (Cache.Put for a domain key),
//     so central keeps a backup + audit trail without ever needing the
//     ACME challenge to resolve at its own IP.
type AgentCertSync struct {
	centralURL string
	apiKey     string
	httpClient *http.Client

	// Pull cache — keyed by lowercase domain. Entries TTL out so a manual
	// cert upload becomes visible within ~60s of the SSE config_updated
	// event without the agent having to reconnect on every change.
	cache atomic.Pointer[pullCache]

	// 404s are remembered separately so the agent does not hammer central
	// with one upstream call per TLS handshake for domains that have no
	// manual cert. Same TTL as positive entries.
	negativeCache atomic.Pointer[pullCache]
}

type pullCache struct {
	mu      sync.Mutex
	entries map[string]pullEntry
}

type pullEntry struct {
	cert *tls.Certificate
	at   time.Time
}

const (
	agentCertCacheTTL = 60 * time.Second
	agentCertTimeout  = 10 * time.Second
)

// NewAgentCertSync builds the sync client. centralURL must be the same one
// the AgentSource uses; apiKey is reused for X-Api-Key auth on the cert
// endpoints. Returns nil when either is empty — call sites then skip the
// sync layer entirely (TLS still works, just without central backup).
func NewAgentCertSync(centralURL, apiKey string) *AgentCertSync {
	if centralURL == "" || apiKey == "" {
		return nil
	}
	s := &AgentCertSync{
		centralURL: strings.TrimRight(centralURL, "/"),
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: agentCertTimeout},
	}
	s.cache.Store(&pullCache{entries: map[string]pullEntry{}})
	s.negativeCache.Store(&pullCache{entries: map[string]pullEntry{}})
	return s
}

// FetchCertificate asks central for a cert for the given domain. Returns
// (nil, nil) when central has no cert on file (typical case — the host
// uses ACME). Returns (nil, err) only on transport / decoding errors so
// callers can fall back to autocert without surfacing a 404 as an error.
func (s *AgentCertSync) FetchCertificate(domain string) (*tls.Certificate, error) {
	if s == nil {
		return nil, nil
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, nil
	}

	// Positive cache hit
	if c := s.cache.Load(); c != nil {
		c.mu.Lock()
		entry, ok := c.entries[domain]
		c.mu.Unlock()
		if ok && time.Since(entry.at) < agentCertCacheTTL {
			return entry.cert, nil
		}
	}
	// Negative cache hit — central confirmed no cert recently
	if c := s.negativeCache.Load(); c != nil {
		c.mu.Lock()
		entry, ok := c.entries[domain]
		c.mu.Unlock()
		if ok && time.Since(entry.at) < agentCertCacheTTL {
			return nil, nil
		}
	}

	cert, err := s.fetchOnce(domain)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		// Remember the miss so we don't poll central per handshake.
		if c := s.negativeCache.Load(); c != nil {
			c.mu.Lock()
			c.entries[domain] = pullEntry{at: time.Now()}
			c.mu.Unlock()
		}
		return nil, nil
	}
	if c := s.cache.Load(); c != nil {
		c.mu.Lock()
		c.entries[domain] = pullEntry{cert: cert, at: time.Now()}
		c.mu.Unlock()
	}
	return cert, nil
}

func (s *AgentCertSync) fetchOnce(domain string) (*tls.Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), agentCertTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET",
		s.centralURL+"/api/v1/agent/cert/"+domain, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", s.apiKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("central returned %d", resp.StatusCode)
	}

	var body struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	cert, err := tls.X509KeyPair([]byte(body.CertPEM), []byte(body.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse PEM: %w", err)
	}
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	if cert.Leaf != nil && time.Now().After(cert.Leaf.NotAfter) {
		// Treat an expired cert from central as no cert at all so we fall
		// back to the agent's autocert flow rather than serving a stale
		// one. The admin should remove or replace the stored cert.
		slog.Warn("central cert is expired, ignoring", "domain", domain)
		return nil, nil
	}
	return &cert, nil
}

// InvalidateCache clears all cached pulls. Called on every config_updated
// SSE event so a manual cert upload is picked up on the next handshake
// without waiting out the TTL.
func (s *AgentCertSync) InvalidateCache() {
	if s == nil {
		return
	}
	s.cache.Store(&pullCache{entries: map[string]pullEntry{}})
	s.negativeCache.Store(&pullCache{entries: map[string]pullEntry{}})
}

// PushCertificate uploads a freshly-issued ACME certificate to central as a
// backup. Called by ReportingCache below after autocert.Cache.Put completes.
// Errors are logged but never returned to the caller — the cert is already
// served locally; missing the central backup is a degraded mode, not a
// fatal one.
func (s *AgentCertSync) PushCertificate(domain string, certKeyPEM []byte) {
	if s == nil {
		return
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return
	}
	certPEM, keyPEM := splitPEMBlocks(certKeyPEM)
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return
	}

	body, _ := json.Marshal(map[string]string{
		"cert_pem": string(certPEM),
		"key_pem":  string(keyPEM),
	})
	ctx, cancel := context.WithTimeout(context.Background(), agentCertTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST",
		s.centralURL+"/api/v1/agent/cert/"+domain, bytes.NewReader(body))
	if err != nil {
		slog.Warn("agent cert push: build request failed", "domain", domain, "error", err)
		return
	}
	req.Header.Set("X-Api-Key", s.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		slog.Warn("agent cert push failed", "domain", domain, "error", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		bs, _ := io.ReadAll(resp.Body)
		slog.Warn("agent cert push rejected", "domain", domain, "status", resp.StatusCode, "body", string(bs))
		return
	}
	slog.Info("agent cert backup pushed to central", "domain", domain)
}

// splitPEMBlocks separates a Cache.Put payload (cert chain + key concatenated
// PEM, the format autocert uses) into its two halves.
func splitPEMBlocks(data []byte) (cert, key []byte) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		encoded := pem.EncodeToMemory(block)
		switch block.Type {
		case "CERTIFICATE":
			cert = append(cert, encoded...)
		case "RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY":
			key = append(key, encoded...)
		}
	}
	return cert, key
}

// ReportingCache wraps an autocert.Cache with the central push hook. Reads
// and deletes pass through unchanged; writes additionally schedule a non-
// blocking PushCertificate when the key looks like a domain (so we skip
// autocert's account/challenge entries).
type ReportingCache struct {
	inner autocert.Cache
	sync  *AgentCertSync
}

// NewReportingCache decorates inner with central reporting. When sync is nil
// (no central configured) the wrapper is transparent.
func NewReportingCache(inner autocert.Cache, sync *AgentCertSync) autocert.Cache {
	if sync == nil {
		return inner
	}
	return &ReportingCache{inner: inner, sync: sync}
}

func (c *ReportingCache) Get(ctx context.Context, key string) ([]byte, error) {
	return c.inner.Get(ctx, key)
}

func (c *ReportingCache) Put(ctx context.Context, key string, data []byte) error {
	if err := c.inner.Put(ctx, key, data); err != nil {
		return err
	}
	if isDomainKey(key) {
		// Async — TLS handshake should not block on a central round trip.
		go c.sync.PushCertificate(key, data)
	}
	return nil
}

func (c *ReportingCache) Delete(ctx context.Context, key string) error {
	return c.inner.Delete(ctx, key)
}

// isDomainKey returns true when an autocert cache key is a domain (the
// shape used for issued certs) rather than an internal key like
// "acme_account+key" or "acme-v02-…+http-01".
func isDomainKey(key string) bool {
	for _, r := range key {
		if r == '+' || r == ' ' {
			return false
		}
	}
	// Bare strings like "letsencrypt-staging" don't contain dots; those
	// are autocert internals. Real domains always have a dot, so this
	// filter avoids reporting them.
	return strings.Contains(key, ".")
}
