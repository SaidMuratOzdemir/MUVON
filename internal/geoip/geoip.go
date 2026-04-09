package geoip

import (
	"log/slog"
	"net"
	"sync/atomic"

	"github.com/oschwald/maxminddb-golang"
)

// Reader provides GeoIP lookups from a local MaxMind .mmdb file.
// It supports atomic reload for zero-downtime DB updates.
type Reader struct {
	db atomic.Pointer[maxminddb.Reader]
}

// cityRecord mirrors the GeoLite2-City structure — only the fields we need.
type cityRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
}

// Open loads a .mmdb file and returns a Reader.
func Open(path string) (*Reader, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	r := &Reader{}
	r.db.Store(db)
	slog.Info("geoip database loaded", "path", path)
	return r, nil
}

// Reload atomically swaps the underlying database.
// The old reader is closed after swap.
func (r *Reader) Reload(path string) error {
	newDB, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	old := r.db.Swap(newDB)
	if old != nil {
		old.Close()
	}
	slog.Info("geoip database reloaded", "path", path)
	return nil
}

// Lookup resolves an IP to country and city.
// Returns empty strings for private/unresolvable IPs.
func (r *Reader) Lookup(ip string) (country, city string) {
	if isPrivateIP(ip) {
		return "", ""
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", ""
	}

	db := r.db.Load()
	if db == nil {
		return "", ""
	}

	var rec cityRecord
	if err := db.Lookup(parsed, &rec); err != nil {
		return "", ""
	}

	country = rec.Country.ISOCode
	if name, ok := rec.City.Names["en"]; ok {
		city = name
	}
	return country, city
}

// Close closes the underlying database.
func (r *Reader) Close() error {
	if db := r.db.Load(); db != nil {
		return db.Close()
	}
	return nil
}

// isPrivateIP checks if an IP is private/loopback/link-local.
func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast()
}
