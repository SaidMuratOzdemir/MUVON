package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"muvon/internal/db"

	"golang.org/x/crypto/acme/autocert"
)

// PGCache implements autocert.Cache backed by PostgreSQL acme_cache table.
// It stores raw autocert data (account keys, challenge tokens, certs) as-is.
type PGCache struct {
	db *db.DB
}

func NewPGCache(database *db.DB) *PGCache {
	return &PGCache{db: database}
}

func (c *PGCache) Get(ctx context.Context, key string) ([]byte, error) {
	data, err := c.db.AcmeCacheGet(ctx, key)
	if err != nil {
		return nil, autocert.ErrCacheMiss
	}
	return data, nil
}

func (c *PGCache) Put(ctx context.Context, key string, data []byte) error {
	// Use transaction so acme_cache and tls_certificates stay consistent
	tx, err := c.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("acme cache begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`INSERT INTO acme_cache (key, data, updated_at)
		 VALUES ($1, $2, NOW())
		 ON CONFLICT (key) DO UPDATE SET data = $2, updated_at = NOW()`,
		key, data,
	)
	if err != nil {
		return fmt.Errorf("acme cache put %s: %w", key, err)
	}

	// If this looks like a TLS cert+key (domain name without special chars),
	// also upsert into tls_certificates so it shows up in the admin panel.
	if looksLikeDomain(key) {
		domain := strings.ToLower(strings.TrimSpace(key))
		certPEM, keyPEM := splitPEM(data)
		if certPEM != nil && keyPEM != nil {
			expiresAt := extractExpiry(certPEM)
			_, err = tx.Exec(ctx,
				`INSERT INTO tls_certificates (domain, cert_pem, key_pem, issuer, expires_at, created_at)
				 VALUES ($1, $2, $3, 'letsencrypt', $4, NOW())
				 ON CONFLICT (domain, issuer) DO UPDATE
				 SET cert_pem = EXCLUDED.cert_pem,
				     key_pem = EXCLUDED.key_pem,
				     expires_at = EXCLUDED.expires_at`,
				domain, certPEM, keyPEM, expiresAt,
			)
			if err != nil {
				return fmt.Errorf("acme cache sync cert %s: %w", key, err)
			}
			slog.Info("Let's Encrypt certificate obtained", "domain", domain, "expires", expiresAt.Format("2006-01-02"))
		}
	}

	return tx.Commit(ctx)
}

func (c *PGCache) Delete(ctx context.Context, key string) error {
	return c.db.AcmeCacheDelete(ctx, key)
}

func looksLikeDomain(key string) bool {
	for _, c := range key {
		if c == '+' || c == ' ' {
			return false
		}
	}
	return true
}

func splitPEM(data []byte) (cert, key []byte) {
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

func extractExpiry(certPEM []byte) time.Time {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Now().Add(90 * 24 * time.Hour)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Now().Add(90 * 24 * time.Hour)
	}
	return cert.NotAfter
}

// CertStore manages TLS certificates with in-memory caching
type CertStore struct {
	db    *db.DB
	mu    sync.RWMutex
	certs map[string]*tls.Certificate
}

func NewCertStore(database *db.DB) *CertStore {
	return &CertStore{
		db:    database,
		certs: make(map[string]*tls.Certificate),
	}
}

func (cs *CertStore) GetCertificate(domain string) (*tls.Certificate, error) {
	cs.mu.RLock()
	cert, ok := cs.certs[domain]
	cs.mu.RUnlock()
	if ok {
		if cert.Leaf != nil && time.Now().After(cert.Leaf.NotAfter) {
			cs.Invalidate(domain)
		} else {
			return cert, nil
		}
	}

	if cs.db == nil {
		return nil, fmt.Errorf("cert store: no database")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dbCert, err := cs.db.GetCertByDomain(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("cert store: %w", err)
	}

	if time.Now().After(dbCert.ExpiresAt) {
		return nil, fmt.Errorf("cert store: certificate expired for %s", domain)
	}

	tlsCert, err := tls.X509KeyPair(dbCert.CertPEM, dbCert.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("cert store: parse cert for %s: %w", domain, err)
	}

	// Parse Leaf so in-memory expiry check works
	if tlsCert.Leaf == nil && len(tlsCert.Certificate) > 0 {
		tlsCert.Leaf, _ = x509.ParseCertificate(tlsCert.Certificate[0])
	}

	cs.mu.Lock()
	cs.certs[domain] = &tlsCert
	cs.mu.Unlock()

	slog.Info("certificate loaded from DB", "domain", domain, "expires", dbCert.ExpiresAt)
	return &tlsCert, nil
}

func (cs *CertStore) Invalidate(domain string) {
	cs.mu.Lock()
	delete(cs.certs, domain)
	cs.mu.Unlock()
}

func (cs *CertStore) InvalidateAll() {
	cs.mu.Lock()
	cs.certs = make(map[string]*tls.Certificate)
	cs.mu.Unlock()
}
