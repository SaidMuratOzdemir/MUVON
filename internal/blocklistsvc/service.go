// Package blocklistsvc wires the edge blocker into a running MUVON process.
//
// The scorer itself knows nothing about the database or the config holder; this
// package owns that plumbing so central and the edge agents can share one
// implementation while persisting through different backends.
package blocklistsvc

import (
	"context"
	"log/slog"
	"time"

	"muvon/internal/blocklist"
	"muvon/internal/config"
)

// Persister records a block decided locally. Central writes straight to
// PostgreSQL; an agent reports it to central over HTTP. A nil Persister is
// valid and means "protect this edge, share nothing".
type Persister interface {
	SaveBlock(ctx context.Context, b blocklist.Block) error
}

// Service keeps a Scorer in step with the config snapshot.
type Service struct {
	scorer  *blocklist.Scorer
	holder  *config.Holder
	persist Persister

	// syncedKeys remembers which centrally-decided blocks are already applied,
	// so a reload does not reapply the same hundred rows every few seconds.
	syncedKeys map[string]time.Time
}

// New builds the service and applies the current snapshot immediately, so the
// process is protected before it serves its first request.
func New(holder *config.Holder, persist Persister) *Service {
	s := &Service{
		holder:     holder,
		persist:    persist,
		syncedKeys: make(map[string]time.Time),
	}

	cfg := holder.Get()
	set, errs := blocklist.Compile(cfg.Blocking.Patterns)
	reportCompileErrors(errs)

	s.scorer = blocklist.New(toScorerConfig(cfg), cfg.Blocking.Settings.Allowlist, set)
	s.scorer.OnBlock(s.record)
	s.applyActive(cfg.Blocking.Active)

	holder.OnReload(func(c *config.Config) { s.apply(c) })
	return s
}

// Scorer exposes the scorer so the proxy handler can be given it.
func (s *Service) Scorer() *blocklist.Scorer { return s.scorer }

// Run sweeps expired state until ctx is done.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.scorer.Sweep()
		}
	}
}

// apply pushes a new snapshot into the scorer.
func (s *Service) apply(cfg *config.Config) {
	set, errs := blocklist.Compile(cfg.Blocking.Patterns)
	reportCompileErrors(errs)

	s.scorer.SetConfig(toScorerConfig(cfg))
	s.scorer.SetAllowlist(cfg.Blocking.Settings.Allowlist)
	s.scorer.SetPatterns(set)
	s.applyActive(cfg.Blocking.Active)
}

// applyActive installs blocks decided elsewhere. Apply is idempotent, but the
// seen-set keeps a reload that carries a thousand rows from doing a thousand
// redundant map writes every few seconds.
func (s *Service) applyActive(blocks []blocklist.Block) {
	for _, b := range blocks {
		if prev, ok := s.syncedKeys[b.Key]; ok && prev.Equal(b.ExpiresAt) {
			continue
		}
		s.scorer.Apply(b)
		s.syncedKeys[b.Key] = b.ExpiresAt
	}
	// Forget keys that have dropped out of the snapshot so a client blocked
	// again later is re-applied rather than skipped.
	for k := range s.syncedKeys {
		found := false
		for _, b := range blocks {
			if b.Key == k {
				found = true
				break
			}
		}
		if !found {
			delete(s.syncedKeys, k)
		}
	}
}

// record persists a locally decided block. Failure is logged and swallowed:
// the block is already in force on this edge, and losing the shared copy is
// strictly better than failing the request that triggered it.
func (s *Service) record(b blocklist.Block) {
	if s.persist == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.persist.SaveBlock(ctx, b); err != nil {
		slog.Warn("blocklist: could not share block with the fleet",
			"key", b.Key, "rule", b.Rule, "error", err)
	}
}

func toScorerConfig(cfg *config.Config) blocklist.Config {
	s := cfg.Blocking.Settings
	c := blocklist.DefaultConfig()
	c.Enabled = s.Enabled
	if s.Threshold > 0 {
		c.Threshold = s.Threshold
	}
	if s.Window > 0 {
		c.Window = s.Window
	}
	if s.BaseTTL > 0 {
		c.BaseTTL = s.BaseTTL
	}
	if s.MaxTTL > 0 {
		c.MaxTTL = s.MaxTTL
	}
	if s.MaxEntries > 0 {
		c.MaxEntries = s.MaxEntries
	}
	return c
}

// reportCompileErrors logs bad rows individually. One malformed pattern must
// never disable the rest of the table, so Compile skips it and we say which.
func reportCompileErrors(errs []error) {
	for _, err := range errs {
		slog.Warn("blocklist: pattern skipped", "error", err)
	}
}
