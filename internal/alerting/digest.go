package alerting

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"muvon/internal/alertrules"
	"muvon/internal/db"
)

// digestAlertLimit bounds how many alerts one digest references.
const digestAlertLimit = 500

// RunDigests queues each channel's daily summary when its hour comes, until
// ctx ends.
func (m *Manager) RunDigests(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.QueueDueDigests(ctx, time.Now()); err != nil && ctx.Err() == nil {
				slog.Warn("alerting: digest pass failed", "error", err)
			}
		}
	}
}

// lastDigestInstant is the most recent moment at or before now when a channel
// with this hour and zone is due a digest.
func lastDigestInstant(now time.Time, hour int, loc *time.Location) time.Time {
	local := now.In(loc)
	due := time.Date(local.Year(), local.Month(), local.Day(), hour, 0, 0, 0, loc)
	if due.After(now) {
		due = time.Date(local.Year(), local.Month(), local.Day()-1, hour, 0, 0, 0, loc)
	}
	return due
}

// QueueDueDigests queues a digest for every channel whose digest time has
// passed since its last one, as of now. A dialog-siem that was down at digest
// time sends the missed digest when it comes back, once, covering everything
// since.
func (m *Manager) QueueDueDigests(ctx context.Context, now time.Time) error {
	snap := m.store.Get()
	queued := false
	err := pgx.BeginFunc(ctx, m.database.Pool, func(tx pgx.Tx) error {
		if ok, err := db.TryAdvisoryLock(ctx, tx, "muvon.alert_digest"); err != nil || !ok {
			return err
		}
		for _, ch := range snap.Channels {
			if !ch.Enabled {
				continue
			}
			loc, err := time.LoadLocation(ch.DigestTimezone)
			if err != nil {
				loc = time.UTC
			}
			due := lastDigestInstant(now, ch.DigestHour, loc)
			last, err := db.ChannelLastDigest(ctx, tx, ch.ID)
			if err != nil {
				return err
			}
			if last != nil && !last.Before(due) {
				continue
			}
			since := due.Add(-24 * time.Hour)
			if last != nil && last.After(since) {
				since = *last
			}
			ids, err := db.DigestAlertIDs(ctx, tx, digestRuleIDs(snap, ch.ID), since, now, digestAlertLimit)
			if err != nil {
				return err
			}
			if len(ids) > 0 {
				if err := db.QueueAlertDeliveries(ctx, tx, ids, []alertrules.Channel{ch}, db.DeliveryDigest, ""); err != nil {
					return err
				}
				queued = true
			}
			if err := db.SetChannelLastDigest(ctx, tx, ch.ID, due); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil && queued {
		m.wake()
	}
	return err
}

// digestRuleIDs lists the digest rules that route to a channel.
func digestRuleIDs(snap *alertrules.Snapshot, channelID string) []string {
	var ids []string
	for _, r := range snap.Rules {
		if r.Delivery != alertrules.DeliveryDigest || !r.Enabled {
			continue
		}
		for _, id := range snap.ChannelIDsFor(r) {
			if id == channelID {
				ids = append(ids, r.ID)
				break
			}
		}
	}
	return ids
}
