package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// --- WAF Rule Queries ---

type WafRule struct {
	ID          int       `json:"id"`
	Pattern     string    `json:"pattern"`
	IsRegex     bool      `json:"is_regex"`
	Category    string    `json:"category"`
	Severity    int       `json:"severity"`
	Description string    `json:"description"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (d *DB) ListWafRules(ctx context.Context) ([]WafRule, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT id, pattern, is_regex, category, severity, COALESCE(description,''), is_active, created_at, updated_at
		 FROM waf_rules ORDER BY category, id`)
	if err != nil {
		return nil, fmt.Errorf("list waf rules: %w", err)
	}
	defer rows.Close()

	var rules []WafRule
	for rows.Next() {
		var r WafRule
		if err := rows.Scan(&r.ID, &r.Pattern, &r.IsRegex, &r.Category, &r.Severity,
			&r.Description, &r.IsActive, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("list waf rules scan: %w", err)
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func (d *DB) ListActiveWafRules(ctx context.Context) ([]WafRule, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT id, pattern, is_regex, category, severity, COALESCE(description,''), is_active, created_at, updated_at
		 FROM waf_rules WHERE is_active = true ORDER BY category, id`)
	if err != nil {
		return nil, fmt.Errorf("list active waf rules: %w", err)
	}
	defer rows.Close()

	var rules []WafRule
	for rows.Next() {
		var r WafRule
		if err := rows.Scan(&r.ID, &r.Pattern, &r.IsRegex, &r.Category, &r.Severity,
			&r.Description, &r.IsActive, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("list active waf rules scan: %w", err)
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func (d *DB) GetWafRule(ctx context.Context, id int) (WafRule, error) {
	var r WafRule
	err := d.Pool.QueryRow(ctx,
		`SELECT id, pattern, is_regex, category, severity, COALESCE(description,''), is_active, created_at, updated_at
		 FROM waf_rules WHERE id = $1`, id,
	).Scan(&r.ID, &r.Pattern, &r.IsRegex, &r.Category, &r.Severity,
		&r.Description, &r.IsActive, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return r, fmt.Errorf("get waf rule: %w", err)
	}
	return r, nil
}

func (d *DB) CreateWafRule(ctx context.Context, pattern, category string, isRegex bool, severity int, description string) (WafRule, error) {
	var r WafRule
	err := d.Pool.QueryRow(ctx,
		`INSERT INTO waf_rules (pattern, is_regex, category, severity, description)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, pattern, is_regex, category, severity, COALESCE(description,''), is_active, created_at, updated_at`,
		pattern, isRegex, category, severity, description,
	).Scan(&r.ID, &r.Pattern, &r.IsRegex, &r.Category, &r.Severity,
		&r.Description, &r.IsActive, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return r, fmt.Errorf("create waf rule: %w", err)
	}
	return r, nil
}

func (d *DB) UpdateWafRule(ctx context.Context, id int, pattern, category string, isRegex bool, severity int, description string, isActive bool) (WafRule, error) {
	var r WafRule
	err := d.Pool.QueryRow(ctx,
		`UPDATE waf_rules SET pattern=$1, is_regex=$2, category=$3, severity=$4, description=$5, is_active=$6, updated_at=now()
		 WHERE id=$7
		 RETURNING id, pattern, is_regex, category, severity, COALESCE(description,''), is_active, created_at, updated_at`,
		pattern, isRegex, category, severity, description, isActive, id,
	).Scan(&r.ID, &r.Pattern, &r.IsRegex, &r.Category, &r.Severity,
		&r.Description, &r.IsActive, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return r, fmt.Errorf("update waf rule: %w", err)
	}
	return r, nil
}

func (d *DB) DeleteWafRule(ctx context.Context, id int) error {
	tag, err := d.Pool.Exec(ctx, `DELETE FROM waf_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete waf rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// --- WAF IP State Queries ---

type WafIPState struct {
	IP              string     `json:"ip"`
	Status          string     `json:"status"`
	CumulativeScore float64    `json:"cumulative_score"`
	LastSeen        time.Time  `json:"last_seen"`
	BanUntil        *time.Time `json:"ban_until,omitempty"`
	BanReason       string     `json:"ban_reason,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func (d *DB) ListWafIPStates(ctx context.Context) ([]WafIPState, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT ip, status, cumulative_score, last_seen, ban_until, COALESCE(ban_reason,''), created_at, updated_at
		 FROM waf_ip_state ORDER BY last_seen DESC`)
	if err != nil {
		return nil, fmt.Errorf("list waf ip states: %w", err)
	}
	defer rows.Close()

	var states []WafIPState
	for rows.Next() {
		var s WafIPState
		if err := rows.Scan(&s.IP, &s.Status, &s.CumulativeScore, &s.LastSeen,
			&s.BanUntil, &s.BanReason, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, fmt.Errorf("list waf ip states scan: %w", err)
		}
		states = append(states, s)
	}
	return states, rows.Err()
}

func (d *DB) UpsertWafIPState(ctx context.Context, ip, status string, score float64, lastSeen time.Time, banUntil *time.Time, banReason string) error {
	_, err := d.Pool.Exec(ctx,
		`INSERT INTO waf_ip_state (ip, status, cumulative_score, last_seen, ban_until, ban_reason, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, now())
		 ON CONFLICT (ip) DO UPDATE SET
		     status = EXCLUDED.status,
		     cumulative_score = EXCLUDED.cumulative_score,
		     last_seen = EXCLUDED.last_seen,
		     ban_until = EXCLUDED.ban_until,
		     ban_reason = EXCLUDED.ban_reason,
		     updated_at = now()`,
		ip, status, score, lastSeen, banUntil, banReason)
	if err != nil {
		return fmt.Errorf("upsert waf ip state: %w", err)
	}
	return nil
}

func (d *DB) DeleteWafIPState(ctx context.Context, ip string) error {
	_, err := d.Pool.Exec(ctx, `DELETE FROM waf_ip_state WHERE ip = $1`, ip)
	return err
}

// --- WAF Exclusion Queries ---

type WafExclusion struct {
	ID        int       `json:"id"`
	RouteID   int       `json:"route_id"`
	RuleID    int       `json:"rule_id"`
	Parameter string    `json:"parameter"`
	Location  string    `json:"location"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

func (d *DB) ListWafExclusions(ctx context.Context) ([]WafExclusion, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT id, route_id, rule_id, COALESCE(parameter,''), COALESCE(location,'all'), COALESCE(reason,''), created_at
		 FROM waf_exclusions ORDER BY route_id, rule_id`)
	if err != nil {
		return nil, fmt.Errorf("list waf exclusions: %w", err)
	}
	defer rows.Close()

	var excl []WafExclusion
	for rows.Next() {
		var e WafExclusion
		if err := rows.Scan(&e.ID, &e.RouteID, &e.RuleID, &e.Parameter, &e.Location, &e.Reason, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("list waf exclusions scan: %w", err)
		}
		excl = append(excl, e)
	}
	return excl, rows.Err()
}

func (d *DB) CreateWafExclusion(ctx context.Context, routeID, ruleID int, parameter, location, reason string) (WafExclusion, error) {
	var e WafExclusion
	err := d.Pool.QueryRow(ctx,
		`INSERT INTO waf_exclusions (route_id, rule_id, parameter, location, reason)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, route_id, rule_id, COALESCE(parameter,''), COALESCE(location,'all'), COALESCE(reason,''), created_at`,
		routeID, ruleID, parameter, location, reason,
	).Scan(&e.ID, &e.RouteID, &e.RuleID, &e.Parameter, &e.Location, &e.Reason, &e.CreatedAt)
	if err != nil {
		return e, fmt.Errorf("create waf exclusion: %w", err)
	}
	return e, nil
}

func (d *DB) DeleteWafExclusion(ctx context.Context, id int) error {
	tag, err := d.Pool.Exec(ctx, `DELETE FROM waf_exclusions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete waf exclusion: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// --- WAF Event Queries ---

type WafEvent struct {
	ID            string          `json:"id"`
	Timestamp     time.Time       `json:"timestamp"`
	RequestID     string          `json:"request_id"`
	ClientIP      string          `json:"client_ip"`
	Host          string          `json:"host"`
	Method        string          `json:"method"`
	Path          string          `json:"path"`
	RequestScore  int             `json:"request_score"`
	IPScore       float64         `json:"ip_score"`
	Action        string          `json:"action"`
	MatchedRules  json.RawMessage `json:"matched_rules"`
	DetectionMode bool            `json:"detection_mode"`
}

func (d *DB) InsertWafEvent(ctx context.Context, ev WafEvent) error {
	_, err := d.Pool.Exec(ctx,
		`INSERT INTO waf_events (timestamp, request_id, client_ip, host, method, path, request_score, ip_score, action, matched_rules, detection_mode)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		ev.Timestamp, ev.RequestID, ev.ClientIP, ev.Host, ev.Method, ev.Path,
		ev.RequestScore, ev.IPScore, ev.Action, ev.MatchedRules, ev.DetectionMode)
	if err != nil {
		return fmt.Errorf("insert waf event: %w", err)
	}
	return nil
}

func (d *DB) SearchWafEvents(ctx context.Context, clientIP, action, host string, limit, offset int) ([]WafEvent, int, error) {
	where := "WHERE 1=1"
	args := []any{}
	argIdx := 1

	if clientIP != "" {
		where += fmt.Sprintf(" AND client_ip = $%d", argIdx)
		args = append(args, clientIP)
		argIdx++
	}
	if action != "" {
		where += fmt.Sprintf(" AND action = $%d", argIdx)
		args = append(args, action)
		argIdx++
	}
	if host != "" {
		where += fmt.Sprintf(" AND host = $%d", argIdx)
		args = append(args, host)
		argIdx++
	}

	// Count
	var total int
	countSQL := "SELECT COUNT(*) FROM waf_events " + where
	if err := d.Pool.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count waf events: %w", err)
	}

	// Fetch
	fetchSQL := fmt.Sprintf(
		`SELECT id::text, timestamp, COALESCE(request_id::text,''), client_ip, COALESCE(host,''), COALESCE(method,''), COALESCE(path,''),
		        request_score, ip_score, action, COALESCE(matched_rules,'[]'), detection_mode
		 FROM waf_events %s ORDER BY timestamp DESC LIMIT $%d OFFSET $%d`,
		where, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := d.Pool.Query(ctx, fetchSQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search waf events: %w", err)
	}
	defer rows.Close()

	var events []WafEvent
	for rows.Next() {
		var e WafEvent
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.RequestID, &e.ClientIP, &e.Host, &e.Method, &e.Path,
			&e.RequestScore, &e.IPScore, &e.Action, &e.MatchedRules, &e.DetectionMode); err != nil {
			return nil, 0, fmt.Errorf("search waf events scan: %w", err)
		}
		events = append(events, e)
	}
	return events, total, rows.Err()
}

// --- WAF VT Cache Queries ---

type WafVTCache struct {
	IP             string    `json:"ip"`
	IsMalicious    bool      `json:"is_malicious"`
	MaliciousCount int       `json:"malicious_count"`
	TotalEngines   int       `json:"total_engines"`
	Reputation     int       `json:"reputation"`
	CheckedAt      time.Time `json:"checked_at"`
}

func (d *DB) GetWafVTCache(ctx context.Context, ip string) (WafVTCache, error) {
	var c WafVTCache
	err := d.Pool.QueryRow(ctx,
		`SELECT ip, is_malicious, malicious_count, total_engines, reputation, checked_at
		 FROM waf_vt_cache WHERE ip = $1`, ip,
	).Scan(&c.IP, &c.IsMalicious, &c.MaliciousCount, &c.TotalEngines, &c.Reputation, &c.CheckedAt)
	return c, err
}

func (d *DB) UpsertWafVTCache(ctx context.Context, ip string, isMalicious bool, maliciousCount, totalEngines, reputation int) error {
	_, err := d.Pool.Exec(ctx,
		`INSERT INTO waf_vt_cache (ip, is_malicious, malicious_count, total_engines, reputation, checked_at)
		 VALUES ($1, $2, $3, $4, $5, now())
		 ON CONFLICT (ip) DO UPDATE SET
		     is_malicious = EXCLUDED.is_malicious,
		     malicious_count = EXCLUDED.malicious_count,
		     total_engines = EXCLUDED.total_engines,
		     reputation = EXCLUDED.reputation,
		     checked_at = now()`,
		ip, isMalicious, maliciousCount, totalEngines, reputation)
	return err
}
