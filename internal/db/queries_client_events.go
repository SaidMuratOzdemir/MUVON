package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ClientEventRow is one materialised row from the client_events hypertable,
// shaped for admin API responses. Optional dimensions are pointers so the
// JSON omits them when NULL.
type ClientEventRow struct {
	ID        string          `json:"id"`
	Time      time.Time       `json:"time"`
	ClientTS  *time.Time      `json:"client_ts,omitempty"`
	App       string          `json:"app"`
	Release   *string         `json:"release,omitempty"`
	HostID    string          `json:"host_id"`
	Host      *string         `json:"host,omitempty"`
	SessionID string          `json:"session_id"`
	ViewID    *string         `json:"view_id,omitempty"`
	Route     *string         `json:"route,omitempty"`
	URLPath   *string         `json:"url_path,omitempty"`
	TraceID   *string         `json:"trace_id,omitempty"`
	SpanID    *string         `json:"span_id,omitempty"`
	EventName string          `json:"event_name"`
	ClientIP  string          `json:"client_ip"`
	Country   *string         `json:"country,omitempty"`
	City      *string         `json:"city,omitempty"`
	UserAgent *string         `json:"user_agent,omitempty"`
	Attrs     json.RawMessage `json:"attrs,omitempty"`
}

// ClientEventSearchParams aggregates every filter the SearchClientEvents
// endpoint understands. Empty / zero fields mean "no filter".
type ClientEventSearchParams struct {
	TraceID   string
	SessionID string
	App       string
	HostID    string
	EventName string
	From      time.Time
	To        time.Time
	Limit     int
	Before    string // cursor (older direction)
}

const clientEventSelectCols = `
    id, time, client_ts, app, release, host_id, host, session_id, view_id,
    route, url_path, trace_id, span_id, event_name, client_ip, country, city,
    user_agent, attrs::jsonb`

// SearchClientEvents runs the cursor-paginated search, newest-first. UUIDv7
// ids are time-ordered, so an id-based `before` cursor walks chronologically
// backwards without a separate (time, id) tuple.
func (d *DB) SearchClientEvents(ctx context.Context, params ClientEventSearchParams) ([]ClientEventRow, error) {
	limit := params.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 5000 {
		limit = 5000
	}

	var conds []string
	args := []any{}
	idx := 0
	push := func(v any) string {
		idx++
		args = append(args, v)
		return fmt.Sprintf("$%d", idx)
	}

	if params.TraceID != "" {
		conds = append(conds, "trace_id = "+push(params.TraceID))
	}
	if params.SessionID != "" {
		conds = append(conds, "session_id = "+push(params.SessionID))
	}
	if params.App != "" {
		conds = append(conds, "app = "+push(params.App))
	}
	if params.HostID != "" {
		conds = append(conds, "host_id = "+push(params.HostID))
	}
	if params.EventName != "" {
		conds = append(conds, "event_name = "+push(params.EventName))
	}
	if !params.From.IsZero() {
		conds = append(conds, "time >= "+push(params.From))
	}
	if !params.To.IsZero() {
		conds = append(conds, "time <= "+push(params.To))
	}
	if params.Before != "" {
		if u, err := uuid.Parse(params.Before); err == nil {
			conds = append(conds, "id < "+push(u))
		}
	}

	var sb strings.Builder
	sb.WriteString("SELECT")
	sb.WriteString(clientEventSelectCols)
	sb.WriteString(" FROM client_events")
	if len(conds) > 0 {
		sb.WriteString(" WHERE ")
		sb.WriteString(strings.Join(conds, " AND "))
	}
	sb.WriteString(" ORDER BY id DESC LIMIT ")
	sb.WriteString(fmt.Sprint(limit))

	rows, err := d.Pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("search client_events: %w", err)
	}
	defer rows.Close()

	out := make([]ClientEventRow, 0, limit)
	for rows.Next() {
		var r ClientEventRow
		var attrs []byte
		if err := rows.Scan(
			&r.ID, &r.Time, &r.ClientTS, &r.App, &r.Release, &r.HostID, &r.Host,
			&r.SessionID, &r.ViewID, &r.Route, &r.URLPath, &r.TraceID, &r.SpanID,
			&r.EventName, &r.ClientIP, &r.Country, &r.City, &r.UserAgent, &attrs,
		); err != nil {
			return nil, fmt.Errorf("scan client_event: %w", err)
		}
		if len(attrs) > 0 {
			r.Attrs = json.RawMessage(attrs)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
