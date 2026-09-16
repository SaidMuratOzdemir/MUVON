package alerting

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"muvon/internal/alertrules"
	"muvon/internal/db"
	"muvon/internal/secret"
)

// Store keeps the current rule and channel snapshot. Raising alerts and
// sending notifications read it on every call, so a change in the panel takes
// effect on the next reload without a restart.
type Store struct {
	database *db.DB
	box      *secret.Box
	snap     atomic.Pointer[alertrules.Snapshot]
}

// NewStore starts with an empty snapshot; call Load before relying on rules.
func NewStore(database *db.DB, box *secret.Box) *Store {
	s := &Store{database: database, box: box}
	s.snap.Store(alertrules.NewSnapshot(nil, nil, nil))
	return s
}

// Get returns the current snapshot. Never nil.
func (s *Store) Get() *alertrules.Snapshot { return s.snap.Load() }

// Load reads rules, channels and project defaults. On failure the previous
// snapshot stays in force.
func (s *Store) Load(ctx context.Context) error {
	channels, err := s.database.ListAlertChannels(ctx)
	if err != nil {
		return err
	}
	for i := range channels {
		if channels[i].SlackWebhook == "" {
			continue
		}
		plain, err := s.box.Decrypt(channels[i].SlackWebhook)
		if err != nil {
			// The channel stays in the snapshot so deliveries to it fail
			// with a reason the panel shows, instead of disappearing.
			slog.Warn("alerting: cannot decrypt channel webhook", "channel", channels[i].Name, "error", err)
			plain = ""
		}
		channels[i].SlackWebhook = plain
	}
	rules, err := s.database.ListAlertRules(ctx)
	if err != nil {
		return err
	}
	projects, err := s.database.ListProjectAlertChannels(ctx)
	if err != nil {
		return err
	}
	s.snap.Store(alertrules.NewSnapshot(channels, rules, projects))
	return nil
}

// Run reloads the snapshot until ctx ends.
func (s *Store) Run(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Load(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("alerting: rule reload failed", "error", err)
			}
		}
	}
}
