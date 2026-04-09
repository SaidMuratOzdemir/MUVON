package config

import (
	"context"
	"log/slog"
	"sync/atomic"

	"muvon/internal/secret"
)

// OnReloadFunc is called after a successful config reload.
type OnReloadFunc func(cfg *Config)

// Holder stores the active Config and manages reloads from any Source.
type Holder struct {
	ptr      atomic.Pointer[Config]
	source   Source
	box      *secret.Box // may be nil for agent mode
	onReload []OnReloadFunc
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

// Reload fetches fresh config from the Source and atomically swaps it in.
// All OnReload callbacks are invoked synchronously after the swap.
func (h *Holder) Reload(ctx context.Context) error {
	cfg, err := h.source.Load(ctx)
	if err != nil {
		slog.Error("config reload failed", "error", err)
		return err
	}
	h.ptr.Store(cfg)
	slog.Info("config reloaded", "hosts", len(cfg.Hosts))

	for _, fn := range h.onReload {
		fn(cfg)
	}
	return nil
}

// OnReload registers a callback invoked after each successful reload.
func (h *Holder) OnReload(fn OnReloadFunc) {
	h.onReload = append(h.onReload, fn)
}

// Init performs the first config load. Alias for Reload.
func (h *Holder) Init(ctx context.Context) error {
	return h.Reload(ctx)
}
