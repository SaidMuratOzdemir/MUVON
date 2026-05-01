package config

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"sync/atomic"

	"muvon/internal/secret"
)

// OnReloadFunc is called after a successful config reload.
type OnReloadFunc func(cfg *Config)

// Holder stores the active Config and manages reloads from any Source.
type Holder struct {
	ptr        atomic.Pointer[Config]
	source     Source
	box        *secret.Box // may be nil for agent mode
	onReload   []OnReloadFunc
	lastDigest atomic.Pointer[[32]byte]
}

// NewHolder creates a Holder backed by the given Source.
// box may be nil when no secret encryption is needed (e.g. agent mode).
func NewHolder(source Source, box *secret.Box) *Holder {
	h := &Holder{
		source: source,
		box:    box,
	}
	h.ptr.Store(&Config{Hosts: make(map[string]*HostConfig)})
	return h
}

// Box returns the secret box used for encrypting/decrypting settings.
// Returns nil in agent mode.
func (h *Holder) Box() *secret.Box {
	return h.box
}

// Get returns the current active Config. Safe for concurrent use.
func (h *Holder) Get() *Config {
	return h.ptr.Load()
}

// Version returns a short string identifying the current config snapshot.
// Used to stamp agent observability rows so the admin UI can tell which
// config version each agent is running. Empty before the first successful
// reload.
func (h *Holder) Version() string {
	d := h.lastDigest.Load()
	if d == nil {
		return ""
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 16)
	for i := 0; i < 8; i++ {
		out[i*2] = hex[d[i]>>4]
		out[i*2+1] = hex[d[i]&0x0f]
	}
	return string(out)
}

// Reload fetches fresh config from the Source and atomically swaps it in.
// All OnReload callbacks are invoked synchronously after the swap.
//
// The reload runs unconditionally on a 5-second background timer in both the
// MUVON and diaLOG processes; without a digest check the same unchanged
// snapshot was reapplied 12× per minute, spamming logs and re-triggering
// every OnReload subscriber (GeoIP reopen, WAF rule reload, ...). We hash
// the source-derived snapshot and skip both the swap and the callbacks when
// nothing changed. The first call (after Init) always proceeds because
// lastDigest starts nil.
func (h *Holder) Reload(ctx context.Context) error {
	cfg, err := h.source.Load(ctx)
	if err != nil {
		slog.Error("config reload failed", "error", err)
		return err
	}

	digest := configDigest(cfg)
	if prev := h.lastDigest.Load(); prev != nil && *prev == digest {
		// Snapshot is byte-identical to the last applied one — skip the
		// swap and callbacks, but keep the most recent ptr so callers
		// reading h.Get() never see a stale value.
		return nil
	}

	h.ptr.Store(cfg)
	h.lastDigest.Store(&digest)
	slog.Info("config reloaded", "hosts", len(cfg.Hosts))

	for _, fn := range h.onReload {
		fn(cfg)
	}
	return nil
}

// configDigest hashes the snapshot. JSON encoding is stable for the maps and
// scalars we use; the one field that does not survive json.Marshal is the
// compiled correlation export regex, so we mix in its source string
// separately. The digest is opaque — used only to detect "is this snapshot
// the same as the last one we applied" and never persisted or compared
// across processes.
func configDigest(cfg *Config) [32]byte {
	h := sha256.New()
	if cfg != nil {
		if buf, err := json.Marshal(cfg); err == nil {
			h.Write(buf)
		}
		if re := cfg.Global.Correlation.ExportPattern; re != nil {
			h.Write([]byte("|export_pattern="))
			h.Write([]byte(re.String()))
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// OnReload registers a callback invoked after each successful reload.
func (h *Holder) OnReload(fn OnReloadFunc) {
	h.onReload = append(h.onReload, fn)
}

// Init performs the first config load. Alias for Reload.
func (h *Holder) Init(ctx context.Context) error {
	return h.Reload(ctx)
}
