package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"muvon/internal/config"
	"muvon/internal/db"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type Manager struct {
	autocertMgr  *autocert.Manager
	certStore    *CertStore
	configHolder *config.Holder
	// agentSync is set on agent binaries to consult central for a manual
	// cert before falling back to ACME, and to push freshly-issued ACME
	// certs back to central. nil on the central server itself.
	agentSync *AgentCertSync
	// localACME remembers domains autocert already has a certificate for, so
	// the handshake path does not read the cache on every request.
	localACME sync.Map
}

func NewManager(database *db.DB, configHolder *config.Holder, adminDomain string) *Manager {
	cfg := configHolder.Get()

	var acmeURL string
	if cfg.Global.LetsEncryptStaging {
		acmeURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	} else {
		acmeURL = "https://acme-v02.api.letsencrypt.org/directory"
	}

	certStore := NewCertStore(database)
	pgCache := NewPGCache(database)

	am := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  pgCache,
		// Central issues only for hosts bound to itself (target_kind=
		// "central"). Hosts bound to an agent are filtered out of the
		// payload an agent receives, so the agent's own autocert handles
		// them — central never burns a Let's Encrypt slot for an edge
		// host it doesn't terminate.
		HostPolicy: hostPolicyFromConfig(configHolder, adminDomain, "central", ""),
		Email:      cfg.Global.LetsEncryptEmail,
		Client:     &acme.Client{DirectoryURL: acmeURL},
	}

	slog.Info("TLS manager initialized",
		"staging", cfg.Global.LetsEncryptStaging,
		"email", cfg.Global.LetsEncryptEmail,
	)

	return &Manager{
		autocertMgr:  am,
		certStore:    certStore,
		configHolder: configHolder,
	}
}

// GetCertificate resolves the certificate for a handshake.
//
// The ordering exists to keep renewal working. autocert only arms its renewal
// timer for certificates it is actually asked to serve, so anything that
// answers ahead of it for an ACME-issued domain silently disables renewal:
// the copy is served until the day it expires, and only then does the fallback
// path issue a new one. That is what happened to this fleet — certificates
// stored centrally as backups were handed back to the agent on every
// handshake, so autocert was never consulted and nothing renewed for months.
//
// Hence: a certificate a human uploaded wins, because that is a deliberate
// override. Otherwise autocert answers for its own certificates, and central's
// copy is what it was meant to be — a backup, used when the agent has nothing
// locally, and seeded into the local cache so autocert takes ownership from
// there on.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := strings.ToLower(hello.ServerName)

	// 1. Operator-uploaded certificate held locally (central only).
	if cert, err := m.certStore.GetOperatorCertificate(domain); err == nil && cert != nil {
		return cert, nil
	}

	// 2. Agent mode — consult central. An operator-uploaded certificate wins
	//    outright; an ACME one is only a backup for step 4.
	var backup *AgentCertSyncResult
	if m.agentSync != nil {
		central, err := m.agentSync.FetchCertificate(domain)
		switch {
		case err != nil:
			slog.Warn("central cert pull failed, falling back to local state", "domain", domain, "error", err)
		case central == nil:
			// Central has nothing; autocert owns this domain.
		case central.OperatorManaged():
			return central.Cert, nil
		default:
			backup = &AgentCertSyncResult{cert: central}
		}
	}

	// 3. autocert already holds this domain: let it serve, which is also what
	//    arms its renewal timer.
	if m.hasLocalACMECert(domain) {
		return m.acmeCertificate(hello, domain, backup)
	}

	// 4. Nothing locally. Seed from central's backup when there is one so the
	//    handshake does not have to wait on ACME and autocert owns the cert
	//    from now on.
	if backup != nil {
		if m.seedLocalACMECert(domain, backup.cert) {
			return m.acmeCertificate(hello, domain, backup)
		}
		slog.Warn("could not seed local cache from central backup, serving it directly", "domain", domain)
		return backup.cert.Cert, nil
	}

	// 5. No certificate anywhere — ask ACME for one.
	slog.Info("requesting certificate from Let's Encrypt", "domain", domain)
	return m.acmeCertificate(hello, domain, nil)
}

// AgentCertSyncResult carries central's copy through GetCertificate without
// widening the exported surface of the pull client.
type AgentCertSyncResult struct{ cert *CentralCert }

// acmeCertificate asks autocert for the certificate, falling back to central's
// backup when ACME cannot answer. Serving a valid backup beats failing the
// handshake because Let's Encrypt is unreachable or rate-limiting us.
func (m *Manager) acmeCertificate(hello *tls.ClientHelloInfo, domain string, backup *AgentCertSyncResult) (*tls.Certificate, error) {
	cert, err := m.autocertMgr.GetCertificate(hello)
	if err == nil {
		return cert, nil
	}
	slog.Error("autocert GetCertificate failed", "domain", domain, "error", err)
	if backup != nil && backup.cert != nil && backup.cert.Cert != nil {
		slog.Warn("serving central's backup certificate instead", "domain", domain)
		return backup.cert.Cert, nil
	}
	return nil, err
}

// hasLocalACMECert reports whether autocert already holds a certificate for
// the domain. The answer is remembered because it only ever flips one way
// (absent to present) within a process, and a handshake must not pay a cache
// read for it every time.
func (m *Manager) hasLocalACMECert(domain string) bool {
	if domain == "" || m.autocertMgr.Cache == nil {
		return false
	}
	if _, ok := m.localACME.Load(domain); ok {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := m.autocertMgr.Cache.Get(ctx, domain); err != nil {
		return false
	}
	m.localACME.Store(domain, struct{}{})
	return true
}

// seedLocalACMECert writes central's backup into autocert's cache so autocert
// adopts the certificate: from the next handshake it serves and renews it
// instead of the copy ageing out untouched. Reports whether the seed landed.
func (m *Manager) seedLocalACMECert(domain string, central *CentralCert) bool {
	if central == nil || len(central.PEM) == 0 || m.autocertMgr.Cache == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.autocertMgr.Cache.Put(ctx, domain, central.PEM); err != nil {
		slog.Warn("seeding autocert cache from central failed", "domain", domain, "error", err)
		return false
	}
	m.localACME.Store(domain, struct{}{})
	slog.Info("adopted central's certificate into the local ACME cache", "domain", domain)
	return true
}

func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	return m.autocertMgr.HTTPHandler(fallback)
}

func (m *Manager) TLSConfig() *tls.Config {
	return HardenedTLSConfig(m.GetCertificate)
}

func (m *Manager) InvalidateCache(domain string) {
	m.certStore.Invalidate(domain)
}

// CertInfo describes the certificate a domain would be served right now,
// established without asking ACME for anything.
type CertInfo struct {
	// Source is where the certificate came from: "manual" for one an operator
	// uploaded, "central" for one pulled from the central store, "acme" for
	// one autocert already holds.
	Source   string
	NotAfter time.Time
	Issuer   string
}

// PeekCertificate reports what is currently being served for domain without
// triggering issuance. Returns nil when nothing is cached anywhere, which for
// an agent-terminated domain is the normal state before its first handshake.
//
// The order mirrors GetCertificate so what this reports is what a handshake
// would actually get, including which layer owns renewal.
func (m *Manager) PeekCertificate(ctx context.Context, domain string) *CertInfo {
	domain = strings.ToLower(strings.TrimSpace(domain))

	if cert, err := m.certStore.GetOperatorCertificate(domain); err == nil && cert != nil {
		if info := certInfoFrom(cert, "manual"); info != nil {
			return info
		}
	}
	if m.agentSync != nil {
		if central, err := m.agentSync.FetchCertificate(domain); err == nil && central != nil && central.OperatorManaged() {
			if info := certInfoFrom(central.Cert, "manual"); info != nil {
				return info
			}
		}
	}
	if m.autocertMgr.Cache != nil {
		if blob, err := m.autocertMgr.Cache.Get(ctx, domain); err == nil {
			if leaf := firstCertificateFromPEM(blob); leaf != nil {
				return &CertInfo{Source: "acme", NotAfter: leaf.NotAfter, Issuer: leaf.Issuer.CommonName}
			}
		}
	}
	return nil
}

// ForceRenew discards every cached copy for domain and obtains a certificate
// immediately rather than waiting for a handshake, so the caller can report
// what actually happened instead of promising a future renewal.
//
// autocert only goes back to the CA when the cached certificate is missing or
// close to expiry, which is why dropping the cache first is what makes this a
// renewal at all. A certificate an operator uploaded still wins on the serving
// path afterwards, so central has to release that copy for a newly issued one
// to be used.
func (m *Manager) ForceRenew(ctx context.Context, domain string) (*CertInfo, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, fmt.Errorf("domain required")
	}

	m.certStore.Invalidate(domain)
	if m.agentSync != nil {
		m.agentSync.InvalidateCache()
	}
	if m.autocertMgr.Cache != nil {
		m.localACME.Delete(domain)
		if err := m.autocertMgr.Cache.Delete(ctx, domain); err != nil {
			return nil, fmt.Errorf("dropping cached certificate: %w", err)
		}
	}

	cert, err := m.autocertMgr.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
	if err != nil {
		return nil, fmt.Errorf("obtaining certificate: %w", err)
	}
	m.localACME.Store(domain, struct{}{})
	info := certInfoFrom(cert, "acme")
	if info == nil {
		return nil, fmt.Errorf("issued certificate could not be parsed")
	}
	return info, nil
}

func certInfoFrom(cert *tls.Certificate, source string) *CertInfo {
	leaf := cert.Leaf
	if leaf == nil {
		if len(cert.Certificate) == 0 {
			return nil
		}
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil
		}
		leaf = parsed
	}
	return &CertInfo{Source: source, NotAfter: leaf.NotAfter, Issuer: leaf.Issuer.CommonName}
}

// firstCertificateFromPEM pulls the leaf out of an autocert cache blob, which
// holds the private key followed by the certificate chain.
func firstCertificateFromPEM(blob []byte) *x509.Certificate {
	for {
		var block *pem.Block
		block, blob = pem.Decode(blob)
		if block == nil {
			return nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil
		}
		return leaf
	}
}

// InvalidateMissing removes in-memory cached certs for domains
// that are no longer present in the active config. On agent mode it also
// drops the central pull cache so a manual cert upload is picked up on the
// next handshake without waiting for the TTL.
func (m *Manager) InvalidateMissing(cfg *config.Config) {
	m.certStore.mu.RLock()
	var stale []string
	for domain := range m.certStore.certs {
		if _, ok := cfg.Hosts[domain]; !ok {
			stale = append(stale, domain)
		}
	}
	m.certStore.mu.RUnlock()
	for _, domain := range stale {
		m.certStore.Invalidate(domain)
		slog.Info("TLS cache invalidated for removed host", "domain", domain)
	}
	// Cheap on the agent (resets a 60-second TTL map); a no-op on central.
	if m.agentSync != nil {
		m.agentSync.InvalidateCache()
	}
}

func hostPolicyFromConfig(ch *config.Holder, adminDomain, selfKind, selfAgentID string) autocert.HostPolicy {
	return func(ctx context.Context, host string) error {
		return hostPolicyCheck(ch, host, adminDomain, selfKind, selfAgentID)
	}
}

// NewManagerNoDB creates a TLS manager that does not require a database.
// ACME certs are cached in the given directory (or in-memory if empty).
// Used by agent binaries running on client servers.
//
// When sync is non-nil the manager additionally consults central for manual
// cert overrides (FetchCertificate) and pushes ACME-issued certs back as a
// backup (via ReportingCache wrapped around the local cache). Pass nil to
// keep the agent fully decoupled from central — useful for offline tests.
func NewManagerNoDB(configHolder *config.Holder, cacheDir string, sync *AgentCertSync) *Manager {
	cfg := configHolder.Get()

	var acmeURL string
	if cfg.Global.LetsEncryptStaging {
		acmeURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	} else {
		acmeURL = "https://acme-v02.api.letsencrypt.org/directory"
	}

	var cache autocert.Cache
	if cacheDir != "" {
		cache = autocert.DirCache(cacheDir)
	} else {
		cache = newMemCache()
	}
	cache = NewReportingCache(cache, sync)

	am := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  cache,
		// Agents are scoped already by config payload filtering — any host
		// they see is theirs to terminate. Pass selfKind/agentID empty so
		// the policy only enforces tls_mode rules, not ownership.
		HostPolicy: hostPolicyFromConfig(configHolder, "", "", ""),
		Email:      cfg.Global.LetsEncryptEmail,
		Client:     &acme.Client{DirectoryURL: acmeURL},
	}

	slog.Info("TLS manager (no-DB) initialized",
		"staging", cfg.Global.LetsEncryptStaging,
		"email", cfg.Global.LetsEncryptEmail,
		"cache_dir", cacheDir,
		"central_sync", sync != nil,
	)

	return &Manager{
		autocertMgr:  am,
		certStore:    &CertStore{certs: make(map[string]storedCert)}, // no DB
		configHolder: configHolder,
		agentSync:    sync,
	}
}

// memCache is an in-memory autocert.Cache implementation.
type memCache struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemCache() *memCache {
	return &memCache{data: make(map[string][]byte)}
}

func (c *memCache) Get(_ context.Context, key string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.data[key]
	if !ok {
		return nil, autocert.ErrCacheMiss
	}
	return v, nil
}

func (c *memCache) Put(_ context.Context, key string, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = data
	return nil
}

func (c *memCache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, key)
	return nil
}

func hostPolicyCheck(ch *config.Holder, host, adminDomain, selfKind, selfAgentID string) error {
	host = strings.ToLower(host)
	if adminDomain != "" && host == strings.ToLower(adminDomain) {
		return nil
	}
	cfg := ch.Get()
	hc, ok := cfg.Hosts[host]
	if !ok {
		slog.Warn("TLS host policy rejected", "host", host)
		return fmt.Errorf("host %q not configured", host)
	}
	// Ownership: if this instance is identified (central or a specific
	// agent), refuse ACME for hosts bound to a different terminator. The
	// proxy layer also returns 421 for these, but stopping the policy
	// here avoids hammering Let's Encrypt's rate limit during a
	// misconfiguration window.
	if selfKind != "" {
		switch hc.Host.TargetKind {
		case "central":
			if selfKind != "central" {
				return fmt.Errorf("host %q is bound to central; ACME skipped on this instance", host)
			}
		case "agent":
			if selfKind != "agent" || selfAgentID == "" {
				return fmt.Errorf("host %q is bound to an edge agent; central skips ACME", host)
			}
			if hc.Host.TargetAgentID == nil || *hc.Host.TargetAgentID != selfAgentID {
				return fmt.Errorf("host %q is bound to a different agent", host)
			}
		}
	}
	// tls_mode picks whether autocert may issue for this host:
	//   "auto"     — ACME issuance (default)
	//   "redirect" — listener serves HTTPS too, ACME issues normally
	//   "manual"   — admin uploads cert; never ask Let's Encrypt
	//   "off"      — no HTTPS listener at all
	switch hc.Host.TLSMode {
	case "", "auto", "redirect":
		return nil
	case "manual":
		return fmt.Errorf("host %q uses manual cert; ACME skipped", host)
	case "off":
		return fmt.Errorf("host %q has tls_mode=off; no HTTPS", host)
	default:
		return nil
	}
}
