package geoip

import (
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// State labels match the strings exposed via gRPC and consumed by the admin
// UI; keep the set aligned with proto/logpb/log.proto::EnrichmentStatusResponse.
const (
	StateDisabled = "disabled"
	StateOK       = "ok"
	StateError    = "error"
)

// Status is an immutable snapshot of the loader's last attempt.
type Status struct {
	State    string    // disabled | ok | error
	Path     string    // path the loader tried (post-trim)
	Error    string    // last error message when State == "error"
	LoadedAt time.Time // zero when not loaded
}

// Manager wraps a Reader with the bookkeeping needed to surface load failures
// to operators. The previous code path silently dropped errors from
// geoip.Open / Reload, which left empty country columns with no visible
// cause when a setting was mistyped (e.g. a leading space in the path).
//
// Apply applies a desired (enabled, path) configuration and is idempotent —
// calling it on every config reload only opens the file when (enabled, path)
// actually changes, so the hot path is not paying maxminddb.Open per tick.
type Manager struct {
	mu     sync.Mutex
	reader atomic.Pointer[Reader]
	status atomic.Pointer[Status]

	// Last applied configuration — protected by mu, used to make Apply idempotent.
	lastEnabled bool
	lastPath    string
}

// NewManager builds a Manager in the disabled state.
func NewManager() *Manager {
	m := &Manager{}
	m.status.Store(&Status{State: StateDisabled})
	return m
}

// Reader returns the currently active *Reader, or nil when GeoIP is disabled or
// the last load attempt failed. Callers in the hot enrichment path must tolerate
// nil — an unavailable GeoIP must never block log ingestion.
func (m *Manager) Reader() *Reader {
	return m.reader.Load()
}

// GetStatus returns a copy of the latest load status. Safe for concurrent use.
func (m *Manager) GetStatus() Status {
	if s := m.status.Load(); s != nil {
		return *s
	}
	return Status{State: StateDisabled}
}

// Apply reconciles the manager state with the desired (enabled, path).
// Returns nil when the operation succeeds OR when GeoIP is desired-disabled;
// returns the load error otherwise. The error is also captured in the status
// snapshot so admin surfaces can display it without retrieving it inline.
func (m *Manager) Apply(enabled bool, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Disabled — drop any open reader and record the desired state.
	if !enabled || path == "" {
		if cur := m.reader.Swap(nil); cur != nil {
			_ = cur.Close()
		}
		m.lastEnabled = false
		m.lastPath = path
		m.status.Store(&Status{State: StateDisabled, Path: path})
		return nil
	}

	// Already in the desired state and previously loaded successfully —
	// avoid re-reading the .mmdb file on every config tick.
	if m.lastEnabled && m.lastPath == path {
		if r := m.reader.Load(); r != nil {
			return nil
		}
	}

	// (Re)open. Swap atomically so the enrichment path never sees a stale
	// reader after a successful reload.
	r, err := Open(path)
	if err != nil {
		m.status.Store(&Status{State: StateError, Path: path, Error: err.Error()})
		slog.Warn("geoip apply failed", "path", path, "error", err)
		return err
	}
	if cur := m.reader.Swap(r); cur != nil {
		_ = cur.Close()
	}
	m.lastEnabled = true
	m.lastPath = path
	m.status.Store(&Status{State: StateOK, Path: path, LoadedAt: time.Now()})
	return nil
}

// Lookup is a convenience wrapper that no-ops when GeoIP is unavailable.
// It mirrors Reader.Lookup so callers can swap to Manager without changes.
func (m *Manager) Lookup(ip string) (country, city string) {
	r := m.reader.Load()
	if r == nil {
		return "", ""
	}
	return r.Lookup(ip)
}

// Close releases the underlying database. Subsequent Apply calls work as usual.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur := m.reader.Swap(nil); cur != nil {
		return cur.Close()
	}
	return errors.New("geoip manager: no reader to close")
}
