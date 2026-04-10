package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"muvon/internal/config"
	"muvon/internal/db"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type Manager struct {
	autocertMgr *autocert.Manager
	certStore   *CertStore
	configHolder *config.Holder
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
		Prompt:     autocert.AcceptTOS,
		Cache:      pgCache,
		HostPolicy: hostPolicyFromConfig(configHolder, adminDomain),
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

func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := strings.ToLower(hello.ServerName)

	// Önce DB'den (manuel yüklenen veya önceden cached sertifika)
	cert, err := m.certStore.GetCertificate(domain)
	if err == nil {
		return cert, nil
	}

	// Sonra autocert (Let's Encrypt)
	slog.Info("requesting certificate from Let's Encrypt", "domain", domain)
	cert, err = m.autocertMgr.GetCertificate(hello)
	if err != nil {
		slog.Error("autocert GetCertificate failed", "domain", domain, "error", err)
	}
	return cert, err
}

func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	return m.autocertMgr.HTTPHandler(fallback)
}

func (m *Manager) TLSConfig() *tls.Config {
	return HardenedTLSConfig(m.GetCertificate)
}

func (m *Manager) AutocertManager() *autocert.Manager {
	return m.autocertMgr
}

func (m *Manager) InvalidateCache(domain string) {
	m.certStore.Invalidate(domain)
}

// InvalidateMissing removes in-memory cached certs for domains
// that are no longer present in the active config.
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
}

func hostPolicyFromConfig(ch *config.Holder, adminDomain string) autocert.HostPolicy {
	return func(ctx context.Context, host string) error {
		return hostPolicyCheck(ch, host, adminDomain)
	}
}

// NewManagerNoDB creates a TLS manager that does not require a database.
// ACME certs are cached in the given directory (or in-memory if empty).
// Used by agent binaries running on client servers.
func NewManagerNoDB(configHolder *config.Holder, cacheDir string) *Manager {
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

	am := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      cache,
		HostPolicy: hostPolicyFromConfig(configHolder, ""),
		Email:      cfg.Global.LetsEncryptEmail,
		Client:     &acme.Client{DirectoryURL: acmeURL},
	}

	slog.Info("TLS manager (no-DB) initialized",
		"staging", cfg.Global.LetsEncryptStaging,
		"email", cfg.Global.LetsEncryptEmail,
		"cache_dir", cacheDir,
	)

	return &Manager{
		autocertMgr:  am,
		certStore:    &CertStore{certs: make(map[string]*tls.Certificate)}, // no DB
		configHolder: configHolder,
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

func hostPolicyCheck(ch *config.Holder, host, adminDomain string) error {
	host = strings.ToLower(host)
	if adminDomain != "" && host == strings.ToLower(adminDomain) {
		return nil
	}
	cfg := ch.Get()
	if _, ok := cfg.Hosts[host]; ok {
		return nil
	}
	slog.Warn("TLS host policy rejected", "host", host)
	return fmt.Errorf("host %q not configured", host)
}
