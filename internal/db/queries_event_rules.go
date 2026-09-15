package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// EventRuleHit is one log line an event rule matched.
type EventRuleHit struct {
	RuleID      string
	DedupKey    string
	GroupKey    string
	OccurredAt  time.Time
	LogID       string
	ContainerID string
	Project     string
	Component   string
	EventName   string
	Fields      map[string]string
	Line        string
}

// InsertEventRuleHits records hits in the caller's transaction, skipping ones
// already recorded for the same rule and line. It returns how many were new.
func InsertEventRuleHits(ctx context.Context, tx pgx.Tx, hits []EventRuleHit) (int64, error) {
	if len(hits) == 0 {
		return 0, nil
	}
	var (
		ruleIDs, dedup, groups, logIDs, containers, projects, components, names, fields, lines []string
		occurred                                                                               []time.Time
	)
	for _, h := range hits {
		f, err := json.Marshal(h.Fields)
		if err != nil {
			return 0, fmt.Errorf("encode hit fields: %w", err)
		}
		ruleIDs = append(ruleIDs, h.RuleID)
		dedup = append(dedup, h.DedupKey)
		groups = append(groups, h.GroupKey)
		occurred = append(occurred, h.OccurredAt)
		logIDs = append(logIDs, h.LogID)
		containers = append(containers, h.ContainerID)
		projects = append(projects, h.Project)
		components = append(components, h.Component)
		names = append(names, h.EventName)
		fields = append(fields, string(f))
		lines = append(lines, h.Line)
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO dialog.event_rule_hits
		  (rule_id, dedup_key, group_key, occurred_at, log_id, container_id, project, component, event_name, fields, line)
		SELECT r::uuid, d, g, o, l::uuid, c, p, co, n, f::jsonb, li
		FROM unnest($1::text[], $2::text[], $3::text[], $4::timestamptz[], $5::text[], $6::text[],
		            $7::text[], $8::text[], $9::text[], $10::text[], $11::text[])
		     AS t(r, d, g, o, l, c, p, co, n, f, li)
		ON CONFLICT (rule_id, dedup_key) DO NOTHING`,
		ruleIDs, dedup, groups, occurred, logIDs, containers, projects, components, names, fields, lines)
	if err != nil {
		return 0, fmt.Errorf("insert event rule hits: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ClaimPendingHits locks hits the evaluator has not processed, oldest first.
func ClaimPendingHits(ctx context.Context, tx pgx.Tx, limit int) ([]EventRuleHit, error) {
	rows, err := tx.Query(ctx, `
		SELECT rule_id::text, dedup_key, group_key, occurred_at, log_id::text, container_id,
		       project, component, event_name, fields, line
		FROM dialog.event_rule_hits
		WHERE evaluated_at IS NULL
		ORDER BY created_at, occurred_at
		LIMIT $1
		FOR UPDATE SKIP LOCKED`, limit)
	if err != nil {
		return nil, fmt.Errorf("claim pending hits: %w", err)
	}
	return scanHits(rows)
}

func scanHits(rows pgx.Rows) ([]EventRuleHit, error) {
	defer rows.Close()
	out := []EventRuleHit{}
	for rows.Next() {
		var h EventRuleHit
		var fieldsRaw []byte
		if err := rows.Scan(&h.RuleID, &h.DedupKey, &h.GroupKey, &h.OccurredAt, &h.LogID, &h.ContainerID,
			&h.Project, &h.Component, &h.EventName, &fieldsRaw, &h.Line); err != nil {
			return nil, fmt.Errorf("scan hit: %w", err)
		}
		if len(fieldsRaw) > 0 {
			if err := json.Unmarshal(fieldsRaw, &h.Fields); err != nil {
				return nil, fmt.Errorf("decode hit fields: %w", err)
			}
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// MarkHitsEvaluated records that the evaluator has processed hits.
func MarkHitsEvaluated(ctx context.Context, tx pgx.Tx, hits []EventRuleHit) error {
	if len(hits) == 0 {
		return nil
	}
	ruleIDs := make([]string, len(hits))
	keys := make([]string, len(hits))
	for i, h := range hits {
		ruleIDs[i], keys[i] = h.RuleID, h.DedupKey
	}
	if _, err := tx.Exec(ctx, `
		UPDATE dialog.event_rule_hits h SET evaluated_at = now()
		FROM unnest($1::text[], $2::text[]) AS k(rule_id, dedup_key)
		WHERE h.rule_id = k.rule_id::uuid AND h.dedup_key = k.dedup_key`, ruleIDs, keys); err != nil {
		return fmt.Errorf("mark hits evaluated: %w", err)
	}
	return nil
}

// CountRuleHits counts a group's hits in (since, until].
func CountRuleHits(ctx context.Context, tx pgx.Tx, ruleID, groupKey string, since, until time.Time) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `
		SELECT count(*) FROM dialog.event_rule_hits
		WHERE rule_id = $1::uuid AND group_key = $2 AND occurred_at > $3 AND occurred_at <= $4`,
		ruleID, groupKey, since, until).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count rule hits: %w", err)
	}
	return n, nil
}

// CountDistinctRuleHitField counts the different values of a field among a
// group's hits in (since, until]. Hits without the field do not count.
func CountDistinctRuleHitField(ctx context.Context, tx pgx.Tx, ruleID, groupKey, field string, since, until time.Time) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `
		SELECT count(DISTINCT fields->>$3) FROM dialog.event_rule_hits
		WHERE rule_id = $1::uuid AND group_key = $2 AND occurred_at > $4 AND occurred_at <= $5
		  AND fields ? $3`,
		ruleID, groupKey, field, since, until).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count distinct rule hits: %w", err)
	}
	return n, nil
}

// RuleHitsInWindow returns up to limit of a group's hits in (since, until],
// the earliest first, so an alert shows the lines that opened it.
func RuleHitsInWindow(ctx context.Context, tx pgx.Tx, ruleID, groupKey string, since, until time.Time, limit int) ([]EventRuleHit, error) {
	rows, err := tx.Query(ctx, `
		SELECT rule_id::text, dedup_key, group_key, occurred_at, log_id::text, container_id,
		       project, component, event_name, fields, line
		FROM dialog.event_rule_hits
		WHERE rule_id = $1::uuid AND group_key = $2 AND occurred_at > $3 AND occurred_at <= $4
		ORDER BY occurred_at
		LIMIT $5`, ruleID, groupKey, since, until, limit)
	if err != nil {
		return nil, fmt.Errorf("rule hits in window: %w", err)
	}
	return scanHits(rows)
}

// LastAcknowledgedAt returns when the latest closed alert for a fingerprint
// was acknowledged, or nil. A threshold has to be crossed again after it.
func LastAcknowledgedAt(ctx context.Context, tx pgx.Tx, fingerprint string) (*time.Time, error) {
	var at *time.Time
	err := tx.QueryRow(ctx, `
		SELECT max(acknowledged_at) FROM dialog.alerts
		WHERE fingerprint = $1 AND acknowledged`, fingerprint).Scan(&at)
	if err != nil {
		return nil, fmt.Errorf("last acknowledged: %w", err)
	}
	return at, nil
}

// HasOpenAlert reports whether a fingerprint has an unacknowledged alert.
func HasOpenAlert(ctx context.Context, tx pgx.Tx, fingerprint string) (bool, error) {
	var open bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM dialog.alerts WHERE fingerprint = $1 AND NOT acknowledged)`,
		fingerprint).Scan(&open)
	if err != nil {
		return false, fmt.Errorf("open alert: %w", err)
	}
	return open, nil
}

// PurgeEventRuleHits deletes evaluated hits that occurred before cutoff.
// Unevaluated hits stay whatever their age: they are work not yet done.
func (d *DB) PurgeEventRuleHits(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := d.Pool.Exec(ctx,
		`DELETE FROM dialog.event_rule_hits WHERE evaluated_at IS NOT NULL AND occurred_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("purge event rule hits: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ChannelLastDigest returns when a channel's last digest was due, or nil.
func ChannelLastDigest(ctx context.Context, tx pgx.Tx, channelID string) (*time.Time, error) {
	var at *time.Time
	err := tx.QueryRow(ctx,
		`SELECT last_digest_at FROM dialog.alert_channel_state WHERE channel_id = $1::uuid`, channelID).Scan(&at)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("channel last digest: %w", err)
	}
	return at, nil
}

// SetChannelLastDigest records the digest a channel has been sent up to.
func SetChannelLastDigest(ctx context.Context, tx pgx.Tx, channelID string, at time.Time) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO dialog.alert_channel_state (channel_id, last_digest_at) VALUES ($1::uuid, $2)
		ON CONFLICT (channel_id) DO UPDATE SET last_digest_at = EXCLUDED.last_digest_at`,
		channelID, at); err != nil {
		return fmt.Errorf("set channel last digest: %w", err)
	}
	return nil
}

// DigestAlertIDs lists digest-delivered alerts of the given rules active in
// (since, until], most severe and most recent first.
func DigestAlertIDs(ctx context.Context, tx pgx.Tx, ruleIDs []string, since, until time.Time, limit int) ([]string, error) {
	if len(ruleIDs) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT id::text FROM dialog.alerts
		WHERE delivery = 'digest' AND NOT is_test
		  AND rule_id = ANY($1::text[]::uuid[])
		  AND last_seen_at > $2 AND last_seen_at <= $3
		ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'warning' THEN 2 ELSE 1 END DESC,
		         last_seen_at DESC
		LIMIT $4`, ruleIDs, since, until, limit)
	if err != nil {
		return nil, fmt.Errorf("digest alerts: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan digest alert: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ProjectEvent summarises an event name seen in a project's logs.
type ProjectEvent struct {
	Name       string    `json:"name"`
	Count      int       `json:"count"`
	LastSeenAt time.Time `json:"last_seen_at"`
	Fields     []string  `json:"fields"`
}

// projectEventScanLimit bounds the lines one discovery request reads.
const projectEventScanLimit = 20000

// ListProjectEvents lists the event names a project has logged since the given
// time, with the fields they carry, so a rule can be written against what the
// application actually emits. It reads at most the latest 20000 event lines.
func (d *DB) ListProjectEvents(ctx context.Context, project, component string, since time.Time) ([]ProjectEvent, error) {
	rows, err := d.Pool.Query(ctx, `
		WITH ev AS (
			SELECT attrs->>'event.name' AS name, attrs, timestamp
			FROM dialog.container_logs
			WHERE project = $1 AND ($2 = '' OR component = $2)
			  AND timestamp > $3 AND attrs ? 'event.name'
			ORDER BY timestamp DESC
			LIMIT $4
		)
		SELECT name, count(*), max(timestamp),
		       (SELECT COALESCE(array_agg(DISTINCT k ORDER BY k), '{}')
		        FROM ev e2, jsonb_object_keys(e2.attrs) AS k
		        WHERE e2.name = ev.name AND k <> 'event.name')
		FROM ev
		GROUP BY name
		ORDER BY count(*) DESC, name
		LIMIT 200`, project, component, since, projectEventScanLimit)
	if err != nil {
		return nil, fmt.Errorf("list project events: %w", err)
	}
	defer rows.Close()
	out := []ProjectEvent{}
	for rows.Next() {
		var e ProjectEvent
		if err := rows.Scan(&e.Name, &e.Count, &e.LastSeenAt, &e.Fields); err != nil {
			return nil, fmt.Errorf("scan project event: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// TryAdvisoryLock takes a transaction-scoped advisory lock and reports whether
// it was free, so periodic jobs run once across dialog-siem instances.
func TryAdvisoryLock(ctx context.Context, tx pgx.Tx, name string) (bool, error) {
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtext($1))`, name).Scan(&ok); err != nil {
		return false, fmt.Errorf("advisory lock %s: %w", name, err)
	}
	return ok, nil
}
