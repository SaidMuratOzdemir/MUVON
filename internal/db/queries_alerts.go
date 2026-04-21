package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Alert is the read model returned to the admin UI. It mirrors the row in
// dialog.alerts plus the grouping and acknowledgement metadata added by
// later migrations. json tags match the API contract so the UI can consume
// this shape directly.
type Alert struct {
	ID             string          `json:"id"`
	Timestamp      time.Time       `json:"timestamp"`
	Rule           string          `json:"rule"`
	Severity       string          `json:"severity"`
	Title          string          `json:"title"`
	Detail         json.RawMessage `json:"detail,omitempty"`
	SourceIP       string          `json:"source_ip,omitempty"`
	Host           string          `json:"host,omitempty"`
	Fingerprint    string          `json:"fingerprint"`
	Notified       bool            `json:"notified"`
	NotifiedAt     *time.Time      `json:"notified_at,omitempty"`
	Occurrences    int             `json:"occurrences"`
	LastSeenAt     time.Time       `json:"last_seen_at"`
	Acknowledged   bool            `json:"acknowledged"`
	AcknowledgedAt *time.Time      `json:"acknowledged_at,omitempty"`
	AcknowledgedBy string          `json:"acknowledged_by,omitempty"`
}

// AlertSearchParams filters the alert list. All fields are optional; an
// empty params struct returns the most recent page of alerts across all
// rules/severities.
type AlertSearchParams struct {
	Rule         string
	Severity     string
	Host         string
	SourceIP     string
	Fingerprint  string
	Acknowledged *bool // nil = no filter; false = only unacknowledged
	From         time.Time
	To           time.Time
	Limit        int
	Offset       int
}

const alertSelectCols = `
	id::text, timestamp, rule, severity, title, detail,
	COALESCE(source_ip,'') AS source_ip,
	COALESCE(host,'')      AS host,
	fingerprint, notified, notified_at,
	occurrences, last_seen_at,
	acknowledged, acknowledged_at,
	COALESCE(acknowledged_by,'') AS acknowledged_by
`

func scanAlert(scan func(...any) error) (Alert, error) {
	var a Alert
	err := scan(
		&a.ID, &a.Timestamp, &a.Rule, &a.Severity, &a.Title, &a.Detail,
		&a.SourceIP, &a.Host, &a.Fingerprint, &a.Notified, &a.NotifiedAt,
		&a.Occurrences, &a.LastSeenAt,
		&a.Acknowledged, &a.AcknowledgedAt, &a.AcknowledgedBy,
	)
	return a, err
}

// SearchAlerts returns a filtered page of alerts and the total matching
// count (without limit/offset) for pagination headers.
func (d *DB) SearchAlerts(ctx context.Context, p AlertSearchParams) ([]Alert, int, error) {
	if p.Limit <= 0 || p.Limit > 500 {
		p.Limit = 100
	}
	if p.Offset < 0 {
		p.Offset = 0
	}

	var where []string
	var args []any
	idx := 1
	add := func(clause string, val any) {
		where = append(where, fmt.Sprintf(clause, idx))
		args = append(args, val)
		idx++
	}
	if p.Rule != "" {
		add("rule = $%d", p.Rule)
	}
	if p.Severity != "" {
		add("severity = $%d", p.Severity)
	}
	if p.Host != "" {
		add("host = $%d", p.Host)
	}
	if p.SourceIP != "" {
		add("source_ip = $%d", p.SourceIP)
	}
	if p.Fingerprint != "" {
		add("fingerprint = $%d", p.Fingerprint)
	}
	if p.Acknowledged != nil {
		add("acknowledged = $%d", *p.Acknowledged)
	}
	if !p.From.IsZero() {
		add("timestamp >= $%d", p.From)
	}
	if !p.To.IsZero() {
		add("timestamp <= $%d", p.To)
	}

	whereSQL := ""
	if len(where) > 0 {
		whereSQL = "WHERE " + strings.Join(where, " AND ")
	}

	// Count first (using the same args set) so we can report total.
	var total int
	countSQL := fmt.Sprintf(`SELECT COUNT(*) FROM alerts %s`, whereSQL)
	if err := d.Pool.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count alerts: %w", err)
	}

	listSQL := fmt.Sprintf(`SELECT %s FROM alerts %s ORDER BY last_seen_at DESC LIMIT $%d OFFSET $%d`,
		alertSelectCols, whereSQL, idx, idx+1)
	args = append(args, p.Limit, p.Offset)

	rows, err := d.Pool.Query(ctx, listSQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list alerts: %w", err)
	}
	defer rows.Close()

	var alerts []Alert
	for rows.Next() {
		a, err := scanAlert(rows.Scan)
		if err != nil {
			return nil, 0, fmt.Errorf("scan alert: %w", err)
		}
		alerts = append(alerts, a)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iter alerts: %w", err)
	}
	return alerts, total, nil
}

// GetAlert returns a single alert by id. Returns an error compatible with
// pgx.ErrNoRows when the id is unknown so callers can map that to 404.
func (d *DB) GetAlert(ctx context.Context, id string) (Alert, error) {
	sql := fmt.Sprintf(`SELECT %s FROM alerts WHERE id = $1::uuid`, alertSelectCols)
	a, err := scanAlert(d.Pool.QueryRow(ctx, sql, id).Scan)
	if err != nil {
		return a, fmt.Errorf("get alert: %w", err)
	}
	return a, nil
}

// AcknowledgeAlert marks an alert as acknowledged, recording who and when.
// Returns the post-update row so the UI can refresh without an extra GET.
// Re-acknowledgement is a no-op (existing acknowledged_at is preserved).
func (d *DB) AcknowledgeAlert(ctx context.Context, id, user string) (Alert, error) {
	sql := fmt.Sprintf(`
		UPDATE alerts
		SET acknowledged = true,
		    acknowledged_at = COALESCE(acknowledged_at, now()),
		    acknowledged_by = COALESCE(acknowledged_by, $2)
		WHERE id = $1::uuid
		RETURNING %s`, alertSelectCols)
	a, err := scanAlert(d.Pool.QueryRow(ctx, sql, id, user).Scan)
	if err != nil {
		return a, fmt.Errorf("acknowledge alert: %w", err)
	}
	return a, nil
}

// AlertStats summarises the alerts table for the dashboard banner.
type AlertStats struct {
	TotalOpen      int            `json:"total_open"`       // unacknowledged
	TotalAll       int            `json:"total_all"`        // all-time
	ByRule         map[string]int `json:"by_rule"`          // open alerts
	BySeverity     map[string]int `json:"by_severity"`      // open alerts
	LastAlertAt    *time.Time     `json:"last_alert_at,omitempty"`
}

func (d *DB) GetAlertStats(ctx context.Context) (AlertStats, error) {
	s := AlertStats{
		ByRule:     make(map[string]int),
		BySeverity: make(map[string]int),
	}

	if err := d.Pool.QueryRow(ctx,
		`SELECT
			COUNT(*) FILTER (WHERE NOT acknowledged),
			COUNT(*),
			MAX(last_seen_at)
		 FROM alerts`).Scan(&s.TotalOpen, &s.TotalAll, &s.LastAlertAt); err != nil {
		return s, fmt.Errorf("alert stats totals: %w", err)
	}

	rows, err := d.Pool.Query(ctx,
		`SELECT rule, COUNT(*) FROM alerts WHERE NOT acknowledged GROUP BY rule`)
	if err != nil {
		return s, fmt.Errorf("alert stats by rule: %w", err)
	}
	for rows.Next() {
		var rule string
		var count int
		if err := rows.Scan(&rule, &count); err != nil {
			rows.Close()
			return s, err
		}
		s.ByRule[rule] = count
	}
	rows.Close()

	rows, err = d.Pool.Query(ctx,
		`SELECT severity, COUNT(*) FROM alerts WHERE NOT acknowledged GROUP BY severity`)
	if err != nil {
		return s, fmt.Errorf("alert stats by severity: %w", err)
	}
	for rows.Next() {
		var sev string
		var count int
		if err := rows.Scan(&sev, &count); err != nil {
			rows.Close()
			return s, err
		}
		s.BySeverity[sev] = count
	}
	rows.Close()

	return s, nil
}
