package eventrules

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"muvon/internal/alertrules"
	"muvon/internal/db"
)

// evaluateBatch bounds how many hits one pass takes.
const evaluateBatch = 500

// Raiser merges an event into its alert and queues notifications.
type Raiser interface {
	Raise(ctx context.Context, tx pgx.Tx, ev db.AlertEvent, channels []alertrules.Channel) (db.RaiseResult, bool, error)
	Wake()
}

// Evaluator turns recorded hits into alerts.
type Evaluator struct {
	database *db.DB
	rules    SnapshotSource
	raiser   Raiser
	wake     chan struct{}
	now      func() time.Time
}

// NewEvaluator wires an evaluator.
func NewEvaluator(database *db.DB, rules SnapshotSource, raiser Raiser) *Evaluator {
	return &Evaluator{database: database, rules: rules, raiser: raiser, wake: make(chan struct{}, 1), now: time.Now}
}

// Wake asks for a pass now.
func (e *Evaluator) Wake() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// Run evaluates pending hits until ctx ends. The tick covers hits committed
// while a pass was already running and anything left by a restart.
func (e *Evaluator) Run(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		e.drain(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-e.wake:
		}
	}
}

func (e *Evaluator) drain(ctx context.Context) {
	for ctx.Err() == nil {
		n, err := e.evaluateOnce(ctx)
		if err != nil {
			if ctx.Err() == nil {
				slog.Warn("event rules: evaluation failed", "error", err)
			}
			return
		}
		if n < evaluateBatch {
			return
		}
	}
}

type hitGroup struct {
	ruleID   string
	groupKey string
	hits     []db.EventRuleHit
}

// evaluateOnce processes one batch of hits in one transaction: the alerts it
// raises, the notifications it queues and the hits it marks commit together.
func (e *Evaluator) evaluateOnce(ctx context.Context) (int, error) {
	snap := e.rules.Get()
	processed, queued := 0, false
	err := pgx.BeginFunc(ctx, e.database.Pool, func(tx pgx.Tx) error {
		hits, err := db.ClaimPendingHits(ctx, tx, evaluateBatch)
		if err != nil {
			return err
		}
		processed = len(hits)
		for _, g := range groupHits(hits) {
			rule, ok := snap.Rules[g.ruleID]
			if !ok || rule.Kind != alertrules.KindEvent || !rule.Enabled {
				continue // a rule deleted or disabled since the match raises nothing
			}
			q, err := e.evaluateGroup(ctx, tx, snap, rule, g)
			if err != nil {
				return err
			}
			queued = queued || q
		}
		return db.MarkHitsEvaluated(ctx, tx, hits)
	})
	if err == nil && queued {
		e.raiser.Wake()
	}
	return processed, err
}

func groupHits(hits []db.EventRuleHit) []hitGroup {
	byKey := map[string]*hitGroup{}
	var order []string
	for _, h := range hits {
		key := h.RuleID + "\x00" + h.GroupKey
		g, ok := byKey[key]
		if !ok {
			g = &hitGroup{ruleID: h.RuleID, groupKey: h.GroupKey}
			byKey[key] = g
			order = append(order, key)
		}
		g.hits = append(g.hits, h)
	}
	out := make([]hitGroup, 0, len(order))
	for _, k := range order {
		g := byKey[k]
		sort.Slice(g.hits, func(i, j int) bool { return g.hits[i].OccurredAt.Before(g.hits[j].OccurredAt) })
		out = append(out, *g)
	}
	return out
}

// Fingerprint identifies the incident an event rule group belongs to.
func Fingerprint(ruleID, groupKey string) string {
	return "event:" + ruleID + ":" + groupKey
}

// tierOutcome is a tier that holds, with what it counted.
type tierOutcome struct {
	tier  alertrules.Tier
	count int
	since time.Time // window start the evidence is drawn from; zero for each
}

// evaluateGroup raises the alert a group of new hits calls for.
//
// The highest tier that holds decides the severity. When none holds but the
// incident is already open, the hits still count towards it at the lowest
// severity, which never lowers it: an open incident keeps collecting its
// repeats. Windows start no earlier than the last acknowledgement of the same
// incident, so a threshold has to be crossed again after someone closed it.
func (e *Evaluator) evaluateGroup(ctx context.Context, tx pgx.Tx, snap *alertrules.Snapshot, rule alertrules.Rule, g hitGroup) (bool, error) {
	fp := Fingerprint(rule.ID, g.groupKey)
	ref := g.hits[len(g.hits)-1].OccurredAt
	lastAck, err := db.LastAcknowledgedAt(ctx, tx, fp)
	if err != nil {
		return false, err
	}

	var best *tierOutcome
	for i := len(rule.Tiers) - 1; i >= 0; i-- {
		out, holds, err := e.evaluateTier(ctx, tx, rule, rule.Tiers[i], g, ref, lastAck)
		if err != nil {
			return false, err
		}
		if holds {
			best = &out
			break
		}
	}

	severity := rule.Tiers[0].Severity
	if best != nil {
		severity = best.tier.Severity
	} else {
		open, err := db.HasOpenAlert(ctx, tx, fp)
		if err != nil || !open {
			return false, err
		}
	}

	last := g.hits[len(g.hits)-1]
	detail, err := json.Marshal(map[string]any{
		"events": eventNames(g.hits),
		"tier":   describeTier(best),
	})
	if err != nil {
		return false, err
	}
	ev := db.AlertEvent{
		Rule:        alertrules.KindEvent,
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		Severity:    severity,
		Title:       rule.Name,
		Detail:      detail,
		Project:     last.Project,
		Component:   last.Component,
		Fingerprint: fp,
		GroupKey:    g.groupKey,
		Delivery:    rule.Delivery,
		Occurrences: len(g.hits),
		At:          ref,
		Evidence:    evidence(g.hits, rule),
		RemindAfter: time.Duration(rule.RemindMinutes) * time.Minute,
	}
	if best != nil && !best.since.IsZero() {
		window, err := db.RuleHitsInWindow(ctx, tx, rule.ID, g.groupKey, best.since, ref, 20)
		if err != nil {
			return false, err
		}
		ev.OpenOccurrences = best.count
		ev.OpenEvidence = evidence(window, rule)
	}
	_, queued, err := e.raiser.Raise(ctx, tx, ev, snap.ChannelsFor(rule))
	return queued, err
}

// evaluateTier checks one tier at ref, the time of the newest hit in the
// group.
func (e *Evaluator) evaluateTier(ctx context.Context, tx pgx.Tx, rule alertrules.Rule, t alertrules.Tier, g hitGroup, ref time.Time, lastAck *time.Time) (tierOutcome, bool, error) {
	out := tierOutcome{tier: t}
	since := func(window time.Duration) time.Time {
		s := ref.Add(-window)
		if lastAck != nil && lastAck.After(s) {
			s = *lastAck
		}
		return s
	}
	tr := t.Trigger
	switch tr.Type {
	case alertrules.TriggerEach:
		out.count = len(g.hits)
		return out, true, nil

	case alertrules.TriggerCount:
		out.since = since(time.Duration(tr.WindowSeconds) * time.Second)
		n, err := db.CountRuleHits(ctx, tx, rule.ID, g.groupKey, out.since, ref)
		out.count = n
		return out, err == nil && n >= tr.Count, err

	case alertrules.TriggerDistinct:
		out.since = since(time.Duration(tr.WindowSeconds) * time.Second)
		distinct, err := db.CountDistinctRuleHitField(ctx, tx, rule.ID, g.groupKey, tr.Field, out.since, ref)
		if err != nil || distinct < tr.Count {
			return out, false, err
		}
		out.count, err = db.CountRuleHits(ctx, tx, rule.ID, g.groupKey, out.since, ref)
		return out, err == nil, err

	case alertrules.TriggerBaseline:
		day := 24 * time.Hour
		baselineStart := ref.Add(-day - time.Duration(tr.BaselineDays)*day)
		// A rule younger than its baseline has no history to compare with;
		// every event would look like an anomaly against an empty past.
		if rule.CreatedAt.After(baselineStart) {
			return out, false, nil
		}
		out.since = since(day)
		recent, err := db.CountRuleHits(ctx, tx, rule.ID, g.groupKey, out.since, ref)
		if err != nil {
			return out, false, err
		}
		prior, err := db.CountRuleHits(ctx, tx, rule.ID, g.groupKey, baselineStart, ref.Add(-day))
		if err != nil {
			return out, false, err
		}
		out.count = recent
		average := float64(prior) / float64(tr.BaselineDays)
		return out, recent >= tr.Count && float64(recent) > tr.Ratio*average, nil
	}
	return out, false, nil
}

// evidence turns hits into alert evidence carrying only the fields the rule
// chose to report.
func evidence(hits []db.EventRuleHit, rule alertrules.Rule) []db.AlertEvidence {
	out := make([]db.AlertEvidence, 0, len(hits))
	for _, h := range hits {
		fields := map[string]string{}
		for _, k := range rule.NotifyFields {
			if v, ok := h.Fields[k]; ok {
				fields[k] = v
			}
		}
		out = append(out, db.AlertEvidence{
			LogID:        h.LogID,
			LogTimestamp: h.OccurredAt,
			ContainerID:  h.ContainerID,
			Component:    h.Component,
			Line:         h.Line,
			Fields:       fields,
		})
	}
	return out
}

func eventNames(hits []db.EventRuleHit) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range hits {
		if !seen[h.EventName] {
			seen[h.EventName] = true
			out = append(out, h.EventName)
		}
	}
	sort.Strings(out)
	return out
}

func describeTier(t *tierOutcome) map[string]any {
	if t == nil {
		return map[string]any{"type": "repeat"}
	}
	return map[string]any{
		"severity": t.tier.Severity,
		"trigger":  t.tier.Trigger,
		"count":    t.count,
	}
}
