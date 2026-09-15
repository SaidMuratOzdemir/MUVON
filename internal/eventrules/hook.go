// Package eventrules raises alerts from events applications write to their
// logs. Lines are matched as they are stored, in the same transaction, and a
// separate evaluator turns the recorded matches into alerts.
package eventrules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"muvon/internal/alertrules"
	"muvon/internal/db"
	"muvon/internal/logger"
)

// maxHitLine caps the copy of a matched line kept with its hit.
const maxHitLine = 4096

// SnapshotSource provides the current rules.
type SnapshotSource interface {
	Get() *alertrules.Snapshot
}

// Hook records event rule matches as container log lines are committed.
type Hook struct {
	rules SnapshotSource
	wake  func()

	mu        sync.Mutex
	indexedAt *alertrules.Snapshot
	byProject map[string][]alertrules.Rule

	matched atomic.Bool
}

// NewHook matches against rules and calls wake after a commit that recorded
// matches.
func NewHook(rules SnapshotSource, wake func()) *Hook {
	if wake == nil {
		wake = func() {}
	}
	return &Hook{rules: rules, wake: wake}
}

var _ logger.ContainerCommitHook = (*Hook)(nil)

// rulesByProject indexes enabled event rules by project, rebuilt only when
// the snapshot changes. Most lines belong to projects without rules and cost
// one map lookup.
func (h *Hook) rulesByProject() map[string][]alertrules.Rule {
	snap := h.rules.Get()
	h.mu.Lock()
	defer h.mu.Unlock()
	if snap == h.indexedAt {
		return h.byProject
	}
	idx := map[string][]alertrules.Rule{}
	for _, r := range snap.Rules {
		if r.Kind == alertrules.KindEvent && r.Enabled && r.ProjectSlug != "" {
			idx[r.ProjectSlug] = append(idx[r.ProjectSlug], r)
		}
	}
	h.indexedAt, h.byProject = snap, idx
	return idx
}

// InTx records a hit for every rule a line matches.
func (h *Hook) InTx(ctx context.Context, tx logger.HookTx, lines []logger.StoredContainerLine) error {
	idx := h.rulesByProject()
	if len(idx) == 0 {
		return nil
	}
	var hits []db.EventRuleHit
	for _, l := range lines {
		rules := idx[l.Entry.Project]
		if len(rules) == 0 {
			continue
		}
		ev, ok := alertrules.EventFromAttrs(l.Entry.Attrs)
		if !ok {
			continue
		}
		for _, r := range rules {
			if !r.AppliesTo(l.Entry.Project, l.Entry.Component) || !r.Match.Matches(ev) {
				continue
			}
			hits = append(hits, db.EventRuleHit{
				RuleID:      r.ID,
				DedupKey:    dedupKey(l),
				GroupKey:    r.GroupKey(ev),
				OccurredAt:  l.Timestamp,
				LogID:       l.ID.String(),
				ContainerID: l.Entry.ContainerID,
				Project:     l.Entry.Project,
				Component:   l.Entry.Component,
				EventName:   ev.Name,
				Fields:      alertrules.PickFields(ev, r.ReferencedFields()),
				Line:        capLine(l.Entry.Line),
			})
		}
	}
	if len(hits) == 0 {
		return nil
	}
	n, err := db.InsertEventRuleHits(ctx, tx, hits)
	if err != nil {
		return err
	}
	if n > 0 {
		h.matched.Store(true)
	}
	return nil
}

// AfterCommit wakes the evaluator once matches are visible to it.
func (h *Hook) AfterCommit([]logger.StoredContainerLine) {
	if h.matched.CompareAndSwap(true, false) {
		h.wake()
	}
}

// dedupKey identifies a line independently of the row id, so a batch the
// shipper resends after a lost acknowledgement is recognised: same container,
// same Docker timestamp, same position in the stream, same text.
func dedupKey(l logger.StoredContainerLine) string {
	sum := sha256.New()
	sum.Write([]byte(l.Entry.ContainerID))
	sum.Write([]byte{0})
	sum.Write([]byte(l.Timestamp.UTC().Format(time.RFC3339Nano)))
	sum.Write([]byte{0})
	sum.Write([]byte(strconv.FormatInt(l.Entry.Seq, 10)))
	sum.Write([]byte{0})
	sum.Write([]byte(l.Entry.Line))
	return hex.EncodeToString(sum.Sum(nil))[:32]
}

func capLine(s string) string {
	if len(s) <= maxHitLine {
		return s
	}
	cut := maxHitLine
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
