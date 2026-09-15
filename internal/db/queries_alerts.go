package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"muvon/internal/alertrules"
)

// Alert is one incident: it opens when a rule first fires for a fingerprint
// and stays open, collecting occurrences, until someone acknowledges it.
type Alert struct {
	ID             string          `json:"id"`
	Rule           string          `json:"rule"`
	RuleID         string          `json:"rule_id,omitempty"`
	RuleName       string          `json:"rule_name"`
	Severity       string          `json:"severity"`
	Title          string          `json:"title"`
	Detail         json.RawMessage `json:"detail,omitempty"`
	SourceIP       string          `json:"source_ip,omitempty"`
	Host           string          `json:"host,omitempty"`
	Project        string          `json:"project,omitempty"`
	Component      string          `json:"component,omitempty"`
	Fingerprint    string          `json:"fingerprint"`
	GroupKey       string          `json:"group_key,omitempty"`
	Delivery       string          `json:"delivery"`
	IsTest         bool            `json:"is_test"`
	Occurrences    int             `json:"occurrences"`
	FirstSeenAt    time.Time       `json:"first_seen_at"`
	LastSeenAt     time.Time       `json:"last_seen_at"`
	Evidence       json.RawMessage `json:"evidence"`
	NotifiedAt     *time.Time      `json:"notified_at,omitempty"`
	NextReminderAt *time.Time      `json:"next_reminder_at,omitempty"`
	Acknowledged   bool            `json:"acknowledged"`
	AcknowledgedAt *time.Time      `json:"acknowledged_at,omitempty"`
	AcknowledgedBy string          `json:"acknowledged_by,omitempty"`
}

// AlertEvidence points at a log line an alert came from, with a copy of the
// line so the alert stays readable after retention drops the row.
type AlertEvidence struct {
	LogID        string            `json:"log_id"`
	LogTimestamp time.Time         `json:"log_timestamp"`
	ContainerID  string            `json:"container_id"`
	Component    string            `json:"component,omitempty"`
	Line         string            `json:"line"`
	Fields       map[string]string `json:"fields,omitempty"`
}

// Evidence retention per alert: the lines that opened it and the most recent
// ones. The middle of a long incident adds nothing the count does not say.
const (
	alertEvidenceFirst = 5
	alertEvidenceMax   = 20
)

const alertSelectCols = `
	id::text, rule, COALESCE(rule_id::text, ''), rule_name, severity, title, detail,
	COALESCE(source_ip, ''), COALESCE(host, ''), COALESCE(project, ''), COALESCE(component, ''),
	fingerprint, group_key, delivery, is_test, occurrences, first_seen_at, last_seen_at,
	evidence, notified_at, next_reminder_at, acknowledged, acknowledged_at,
	COALESCE(acknowledged_by, '')
`

func scanAlert(scan func(...any) error) (Alert, error) {
	var a Alert
	err := scan(
		&a.ID, &a.Rule, &a.RuleID, &a.RuleName, &a.Severity, &a.Title, &a.Detail,
		&a.SourceIP, &a.Host, &a.Project, &a.Component,
		&a.Fingerprint, &a.GroupKey, &a.Delivery, &a.IsTest, &a.Occurrences, &a.FirstSeenAt, &a.LastSeenAt,
		&a.Evidence, &a.NotifiedAt, &a.NextReminderAt, &a.Acknowledged, &a.AcknowledgedAt,
		&a.AcknowledgedBy,
	)
	return a, err
}

// AlertSearchParams filters the alert list. Every field is optional.
type AlertSearchParams struct {
	Rule         string
	RuleID       string
	Severity     string
	Host         string
	SourceIP     string
	Project      string
	Fingerprint  string
	Acknowledged *bool
	IsTest       *bool
	From         time.Time // on last_seen_at
	To           time.Time
	Limit        int
	Offset       int
}

// SearchAlerts returns a page of alerts, most recently active first, and the
// total matching count.
func (d *DB) SearchAlerts(ctx context.Context, p AlertSearchParams) ([]Alert, int, error) {
	if p.Limit <= 0 || p.Limit > 500 {
		p.Limit = 100
	}
	if p.Offset < 0 {
		p.Offset = 0
	}

	var where []string
	var args []any
	add := func(clause string, val any) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if p.Rule != "" {
		add("rule = $%d", p.Rule)
	}
	if p.RuleID != "" {
		add("rule_id = $%d::uuid", p.RuleID)
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
	if p.Project != "" {
		add("project = $%d", p.Project)
	}
	if p.Fingerprint != "" {
		add("fingerprint = $%d", p.Fingerprint)
	}
	if p.Acknowledged != nil {
		add("acknowledged = $%d", *p.Acknowledged)
	}
	if p.IsTest != nil {
		add("is_test = $%d", *p.IsTest)
	}
	if !p.From.IsZero() {
		add("last_seen_at >= $%d", p.From)
	}
	if !p.To.IsZero() {
		add("last_seen_at <= $%d", p.To)
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = "WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM dialog.alerts `+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count alerts: %w", err)
	}

	args = append(args, p.Limit, p.Offset)
	rows, err := d.Pool.Query(ctx, fmt.Sprintf(
		`SELECT %s FROM dialog.alerts %s ORDER BY last_seen_at DESC LIMIT $%d OFFSET $%d`,
		alertSelectCols, whereSQL, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list alerts: %w", err)
	}
	defer rows.Close()
	alerts := []Alert{}
	for rows.Next() {
		a, err := scanAlert(rows.Scan)
		if err != nil {
			return nil, 0, fmt.Errorf("scan alert: %w", err)
		}
		alerts = append(alerts, a)
	}
	return alerts, total, rows.Err()
}

// GetAlert returns one alert, or an error wrapping pgx.ErrNoRows.
func (d *DB) GetAlert(ctx context.Context, id string) (Alert, error) {
	a, err := scanAlert(d.Pool.QueryRow(ctx,
		`SELECT `+alertSelectCols+` FROM dialog.alerts WHERE id = $1::uuid`, id).Scan)
	if err != nil {
		return a, fmt.Errorf("get alert: %w", err)
	}
	return a, nil
}

// GetAlertsByIDs returns the alerts that still exist among ids.
func (d *DB) GetAlertsByIDs(ctx context.Context, ids []string) ([]Alert, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT `+alertSelectCols+` FROM dialog.alerts WHERE id = ANY($1::text[]::uuid[]) ORDER BY last_seen_at DESC`, ids)
	if err != nil {
		return nil, fmt.Errorf("get alerts: %w", err)
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		a, err := scanAlert(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan alert: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AcknowledgeAlert closes an alert and stops its reminders. The next event
// with the same fingerprint opens a new alert. Acknowledging twice keeps the
// first acknowledgement.
func (d *DB) AcknowledgeAlert(ctx context.Context, id, user string) (Alert, error) {
	a, err := scanAlert(d.Pool.QueryRow(ctx, `
		UPDATE dialog.alerts
		SET acknowledged = true,
		    acknowledged_at = COALESCE(acknowledged_at, now()),
		    acknowledged_by = COALESCE(acknowledged_by, $2),
		    next_reminder_at = NULL
		WHERE id = $1::uuid
		RETURNING `+alertSelectCols, id, user).Scan)
	if err != nil {
		return a, fmt.Errorf("acknowledge alert: %w", err)
	}
	return a, nil
}

// AlertStats summarises open alerts for the panel.
type AlertStats struct {
	TotalOpen   int            `json:"total_open"`
	TotalAll    int            `json:"total_all"`
	ByRule      map[string]int `json:"by_rule"`
	BySeverity  map[string]int `json:"by_severity"`
	LastAlertAt *time.Time     `json:"last_alert_at,omitempty"`
}

func (d *DB) GetAlertStats(ctx context.Context) (AlertStats, error) {
	s := AlertStats{ByRule: map[string]int{}, BySeverity: map[string]int{}}
	if err := d.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE NOT acknowledged), COUNT(*), MAX(last_seen_at)
		FROM dialog.alerts WHERE NOT is_test`).Scan(&s.TotalOpen, &s.TotalAll, &s.LastAlertAt); err != nil {
		return s, fmt.Errorf("alert stats totals: %w", err)
	}
	for _, q := range []struct {
		sql string
		dst map[string]int
	}{
		{`SELECT rule, COUNT(*) FROM dialog.alerts WHERE NOT acknowledged AND NOT is_test GROUP BY rule`, s.ByRule},
		{`SELECT severity, COUNT(*) FROM dialog.alerts WHERE NOT acknowledged AND NOT is_test GROUP BY severity`, s.BySeverity},
	} {
		rows, err := d.Pool.Query(ctx, q.sql)
		if err != nil {
			return s, fmt.Errorf("alert stats: %w", err)
		}
		for rows.Next() {
			var key string
			var n int
			if err := rows.Scan(&key, &n); err != nil {
				rows.Close()
				return s, err
			}
			q.dst[key] = n
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return s, err
		}
	}
	return s, nil
}

// AlertEvent is one firing of a rule, to be merged into its open alert.
type AlertEvent struct {
	Rule        string // builtin key, or "event" for application event rules
	RuleID      string
	RuleName    string
	Severity    string
	Title       string
	Detail      json.RawMessage
	SourceIP    string
	Host        string
	Project     string
	Component   string
	Fingerprint string
	GroupKey    string
	Delivery    string
	IsTest      bool
	// Occurrences is how many events this firing represents.
	Occurrences int
	At          time.Time
	Evidence    []AlertEvidence
	// OpenOccurrences and OpenEvidence replace Occurrences and Evidence when
	// the firing opens a new alert. A threshold rule opens on its Nth event,
	// and the alert should count and show all N, not only the last.
	OpenOccurrences int
	OpenEvidence    []AlertEvidence
	// RemindAfter schedules reminders while the alert is critical and
	// unacknowledged. Zero disables them.
	RemindAfter time.Duration
}

// RaiseResult says what RaiseAlert did, which decides what gets notified.
type RaiseResult struct {
	AlertID   string
	Opened    bool
	Escalated bool
	Severity  string
}

// RaiseAlert merges an event into the open alert for its fingerprint, or opens
// one. It runs in the caller's transaction so the alert, its deliveries and
// whatever produced the event commit together.
//
// Severity only rises within an alert: a warning arriving on an open critical
// alert is counted, not a downgrade. Two raises racing to open the same
// fingerprint meet at the partial unique index; the loser locks the winner's
// row and merges into it.
func RaiseAlert(ctx context.Context, tx pgx.Tx, ev AlertEvent) (RaiseResult, error) {
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	if ev.Occurrences <= 0 {
		ev.Occurrences = 1
	}
	if ev.Delivery == "" {
		ev.Delivery = alertrules.DeliveryNone
	}

	for attempt := 0; attempt < 2; attempt++ {
		var (
			id             string
			severity       string
			evidenceRaw    []byte
			nextReminderAt *time.Time
		)
		err := tx.QueryRow(ctx, `
			SELECT id::text, severity, evidence, next_reminder_at
			FROM dialog.alerts
			WHERE fingerprint = $1 AND NOT acknowledged
			FOR UPDATE`, ev.Fingerprint).Scan(&id, &severity, &evidenceRaw, &nextReminderAt)

		if errors.Is(err, pgx.ErrNoRows) {
			openEvidence, openOccurrences := ev.Evidence, ev.Occurrences
			if len(ev.OpenEvidence) > 0 {
				openEvidence = ev.OpenEvidence
			}
			if ev.OpenOccurrences > 0 {
				openOccurrences = ev.OpenOccurrences
			}
			evidence, err := json.Marshal(capEvidence(nil, openEvidence))
			if err != nil {
				return RaiseResult{}, fmt.Errorf("raise alert: encode evidence: %w", err)
			}
			err = tx.QueryRow(ctx, `
				INSERT INTO dialog.alerts
				  (rule, rule_id, rule_name, severity, title, detail, source_ip, host, project, component,
				   fingerprint, group_key, delivery, is_test, occurrences, first_seen_at, last_seen_at,
				   evidence, next_reminder_at)
				VALUES ($1, NULLIF($2, '')::uuid, $3, $4, $5, $6, NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''), NULLIF($10, ''),
				        $11, $12, $13, $14, $15, $16, $16, $17, $18)
				ON CONFLICT (fingerprint) WHERE NOT acknowledged DO NOTHING
				RETURNING id::text`,
				ev.Rule, ev.RuleID, ev.RuleName, ev.Severity, ev.Title, nullJSON(ev.Detail), ev.SourceIP, ev.Host,
				ev.Project, ev.Component, ev.Fingerprint, ev.GroupKey, ev.Delivery, ev.IsTest, openOccurrences,
				ev.At, evidence, reminderAt(ev, ev.Severity, nil, true)).Scan(&id)
			if errors.Is(err, pgx.ErrNoRows) {
				continue // another raise opened it first; merge into that one
			}
			if err != nil {
				return RaiseResult{}, fmt.Errorf("raise alert: insert: %w", err)
			}
			return RaiseResult{AlertID: id, Opened: true, Severity: ev.Severity}, nil
		}
		if err != nil {
			return RaiseResult{}, fmt.Errorf("raise alert: lookup: %w", err)
		}

		escalated := alertrules.SeverityRank(ev.Severity) > alertrules.SeverityRank(severity)
		newSeverity := severity
		if escalated {
			newSeverity = ev.Severity
		}
		var existing []AlertEvidence
		if len(evidenceRaw) > 0 {
			_ = json.Unmarshal(evidenceRaw, &existing)
		}
		evidence, err := json.Marshal(capEvidence(existing, ev.Evidence))
		if err != nil {
			return RaiseResult{}, fmt.Errorf("raise alert: encode evidence: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE dialog.alerts
			SET occurrences = occurrences + $2,
			    last_seen_at = GREATEST(last_seen_at, $3),
			    severity = $4,
			    title = CASE WHEN $5 THEN $6 ELSE title END,
			    detail = COALESCE($7, detail),
			    rule_name = $8,
			    delivery = $9,
			    source_ip = COALESCE(NULLIF($10, ''), source_ip),
			    host = COALESCE(NULLIF($11, ''), host),
			    evidence = $12,
			    next_reminder_at = $13
			WHERE id = $1::uuid`,
			id, ev.Occurrences, ev.At, newSeverity, escalated, ev.Title, nullJSON(ev.Detail),
			ev.RuleName, ev.Delivery, ev.SourceIP, ev.Host, evidence,
			reminderAt(ev, newSeverity, nextReminderAt, escalated)); err != nil {
			return RaiseResult{}, fmt.Errorf("raise alert: update: %w", err)
		}
		return RaiseResult{AlertID: id, Escalated: escalated, Severity: newSeverity}, nil
	}
	return RaiseResult{}, fmt.Errorf("raise alert: fingerprint %q kept changing", ev.Fingerprint)
}

// reminderAt decides the next reminder. Reminders run only for a critical,
// instantly delivered, real alert; reaching critical starts the clock, and an
// existing schedule is left alone.
func reminderAt(ev AlertEvent, severity string, current *time.Time, becameThisSeverity bool) *time.Time {
	if severity != alertrules.SeverityCritical || ev.RemindAfter <= 0 || ev.IsTest ||
		ev.Delivery != alertrules.DeliveryInstant {
		return nil
	}
	if current != nil && !becameThisSeverity {
		return current
	}
	t := ev.At.Add(ev.RemindAfter)
	return &t
}

// capEvidence keeps the first lines of an alert and the latest ones.
func capEvidence(existing, added []AlertEvidence) []AlertEvidence {
	all := append(append([]AlertEvidence{}, existing...), added...)
	if len(all) <= alertEvidenceMax {
		return all
	}
	tail := alertEvidenceMax - alertEvidenceFirst
	return append(all[:alertEvidenceFirst:alertEvidenceFirst], all[len(all)-tail:]...)
}

func nullJSON(raw json.RawMessage) any {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return raw
}

// AlertDelivery is one notification to one channel.
type AlertDelivery struct {
	ID          string     `json:"id"`
	AlertIDs    []string   `json:"alert_ids"`
	ChannelID   string     `json:"channel_id"`
	ChannelName string     `json:"channel_name"`
	Kind        string     `json:"kind"`
	Severity    string     `json:"severity"`
	Status      string     `json:"status"`
	Attempts    int        `json:"attempts"`
	LastError   string     `json:"last_error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	SentAt      *time.Time `json:"sent_at,omitempty"`
}

// Delivery kinds.
const (
	DeliveryOpened    = "opened"
	DeliveryEscalated = "escalated"
	DeliveryReminder  = "reminder"
	DeliveryDigest    = "digest"
	DeliveryTest      = "test"
)

// Delivery statuses.
const (
	DeliveryPending = "pending"
	DeliverySent    = "sent"
	DeliveryFailed  = "failed"
	DeliverySkipped = "skipped"
)

// QueueAlertDeliveries writes one pending delivery per channel in the caller's
// transaction.
func QueueAlertDeliveries(ctx context.Context, tx pgx.Tx, alertIDs []string, channels []alertrules.Channel, kind, severity string) error {
	for _, c := range channels {
		if _, err := tx.Exec(ctx, `
			INSERT INTO dialog.alert_deliveries (alert_ids, channel_id, channel_name, kind, severity)
			VALUES ($1::text[]::uuid[], $2::uuid, $3, $4, $5)`,
			alertIDs, c.ID, c.Name, kind, severity); err != nil {
			return fmt.Errorf("queue alert delivery: %w", err)
		}
	}
	return nil
}

const alertDeliveryCols = `id::text, alert_ids::text[], channel_id::text, channel_name, kind, severity,
	status, attempts, last_error, created_at, sent_at`

func scanAlertDelivery(scan func(...any) error) (AlertDelivery, error) {
	var d AlertDelivery
	err := scan(&d.ID, &d.AlertIDs, &d.ChannelID, &d.ChannelName, &d.Kind, &d.Severity,
		&d.Status, &d.Attempts, &d.LastError, &d.CreatedAt, &d.SentAt)
	return d, err
}

// ClaimDueDeliveries leases pending deliveries that are due. The lease pushes
// next_attempt_at forward before anything is sent, so a dispatcher that dies
// mid-send leaves the row to be retried once the lease runs out rather than
// stuck, and a second dispatcher never picks the same row meanwhile.
func (d *DB) ClaimDueDeliveries(ctx context.Context, limit int, lease time.Duration) ([]AlertDelivery, error) {
	rows, err := d.Pool.Query(ctx, `
		UPDATE dialog.alert_deliveries
		SET attempts = attempts + 1, next_attempt_at = now() + $2::interval
		WHERE id IN (
			SELECT id FROM dialog.alert_deliveries
			WHERE status = 'pending' AND next_attempt_at <= now()
			ORDER BY next_attempt_at
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING `+alertDeliveryCols, limit, lease.String())
	if err != nil {
		return nil, fmt.Errorf("claim alert deliveries: %w", err)
	}
	defer rows.Close()
	out := []AlertDelivery{}
	for rows.Next() {
		del, err := scanAlertDelivery(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan alert delivery: %w", err)
		}
		out = append(out, del)
	}
	return out, rows.Err()
}

// CompleteDelivery records the outcome of an attempt. retryAt is used only
// when status is pending.
func (d *DB) CompleteDelivery(ctx context.Context, id, status, lastError string, retryAt time.Time) error {
	_, err := d.Pool.Exec(ctx, `
		UPDATE dialog.alert_deliveries
		SET status = $2,
		    last_error = $3,
		    next_attempt_at = CASE WHEN $2 = 'pending' THEN $4 ELSE next_attempt_at END,
		    sent_at = CASE WHEN $2 = 'sent' THEN now() ELSE sent_at END
		WHERE id = $1::uuid`, id, status, lastError, retryAt)
	if err != nil {
		return fmt.Errorf("complete alert delivery: %w", err)
	}
	return nil
}

// MarkAlertsNotified stamps the first successful notification.
func (d *DB) MarkAlertsNotified(ctx context.Context, ids []string) error {
	_, err := d.Pool.Exec(ctx, `
		UPDATE dialog.alerts SET notified_at = COALESCE(notified_at, now())
		WHERE id = ANY($1::text[]::uuid[])`, ids)
	if err != nil {
		return fmt.Errorf("mark alerts notified: %w", err)
	}
	return nil
}

// ListAlertDeliveries returns the notifications sent for an alert, oldest
// first.
func (d *DB) ListAlertDeliveries(ctx context.Context, alertID string) ([]AlertDelivery, error) {
	rows, err := d.Pool.Query(ctx, `
		SELECT `+alertDeliveryCols+` FROM dialog.alert_deliveries
		WHERE alert_ids @> ARRAY[$1::uuid]
		ORDER BY created_at`, alertID)
	if err != nil {
		return nil, fmt.Errorf("list alert deliveries: %w", err)
	}
	defer rows.Close()
	out := []AlertDelivery{}
	for rows.Next() {
		del, err := scanAlertDelivery(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan alert delivery: %w", err)
		}
		out = append(out, del)
	}
	return out, rows.Err()
}

// DueReminder is an open critical alert whose reminder time has come.
type DueReminder struct {
	AlertID  string
	RuleID   string
	Rule     string
	Severity string
}

// ClaimDueReminders locks alerts whose reminder is due, in the caller's
// transaction, so the reminder is queued and rescheduled atomically.
func ClaimDueReminders(ctx context.Context, tx pgx.Tx, limit int) ([]DueReminder, error) {
	rows, err := tx.Query(ctx, `
		SELECT id::text, COALESCE(rule_id::text, ''), rule, severity
		FROM dialog.alerts
		WHERE NOT acknowledged AND next_reminder_at IS NOT NULL AND next_reminder_at <= now()
		ORDER BY next_reminder_at
		LIMIT $1
		FOR UPDATE SKIP LOCKED`, limit)
	if err != nil {
		return nil, fmt.Errorf("claim due reminders: %w", err)
	}
	defer rows.Close()
	out := []DueReminder{}
	for rows.Next() {
		var r DueReminder
		if err := rows.Scan(&r.AlertID, &r.RuleID, &r.Rule, &r.Severity); err != nil {
			return nil, fmt.Errorf("scan due reminder: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetAlertReminder reschedules, or with nil stops, an alert's reminders.
func SetAlertReminder(ctx context.Context, tx pgx.Tx, alertID string, next *time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE dialog.alerts SET next_reminder_at = $2 WHERE id = $1::uuid`, alertID, next); err != nil {
		return fmt.Errorf("set alert reminder: %w", err)
	}
	return nil
}

// PurgeAcknowledgedAlerts deletes alerts acknowledged before cutoff, and
// settled deliveries created before it. Open alerts are never purged.
func (d *DB) PurgeAcknowledgedAlerts(ctx context.Context, cutoff time.Time) (alerts, deliveries int64, err error) {
	tag, err := d.Pool.Exec(ctx,
		`DELETE FROM dialog.alerts WHERE acknowledged AND acknowledged_at < $1`, cutoff)
	if err != nil {
		return 0, 0, fmt.Errorf("purge alerts: %w", err)
	}
	alerts = tag.RowsAffected()
	tag, err = d.Pool.Exec(ctx,
		`DELETE FROM dialog.alert_deliveries WHERE status <> 'pending' AND created_at < $1`, cutoff)
	if err != nil {
		return alerts, 0, fmt.Errorf("purge alert deliveries: %w", err)
	}
	return alerts, tag.RowsAffected(), nil
}
