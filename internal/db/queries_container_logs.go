package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ContainerLogRow is one materialised row from the container_logs
// hypertable, shaped for both API responses and the dimension upsert
// path used by the deployer's logship.
type ContainerLogRow struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	ReceivedAt    time.Time `json:"received_at"`
	HostID        string    `json:"host_id"`
	ContainerID   string    `json:"container_id"`
	ContainerName string    `json:"container_name"`
	Image         *string   `json:"image,omitempty"`
	Project       *string   `json:"project,omitempty"`
	Component     *string   `json:"component,omitempty"`
	ReleaseID     *string   `json:"release_id,omitempty"`
	DeploymentID  *string   `json:"deployment_id,omitempty"`
	Stream        string    `json:"stream"`
	Line          string    `json:"line"`
	Truncated     bool      `json:"truncated"`
	Seq           int64     `json:"seq"`
	// Attrs is the raw JSONB payload, opaque on the wire so the SIEM does
	// not have to predict the shape the UI wants. Nil when the column is
	// NULL.
	Attrs json.RawMessage `json:"attrs,omitempty"`
}

// ContainerSearchParams is the aggregate of every filter the
// SearchContainerLogs endpoint understands. Empty / zero fields mean
// "no filter on this dimension".
type ContainerSearchParams struct {
	ContainerID   string
	ContainerName string
	Project       string
	Component     string
	ReleaseID     string
	DeploymentID  string
	HostID        string
	Stream        string // "" | "stdout" | "stderr"
	From          time.Time
	To            time.Time
	Query         string            // free-text ILIKE
	Regex         bool              // POSIX regex when true
	Attrs         map[string]string // jsonb_path_ops @>
	Limit         int
	Before        string // cursor (older direction)
	After         string // cursor (newer direction)
}

const containerLogSelectCols = `
    id, timestamp, received_at, host_id, container_id, container_name, image,
    project, component, release_id, deployment_id::text, stream, line,
    truncated, seq, attrs::jsonb`

// SearchContainerLogs runs the cursor-paginated search. UUIDv7 ids are
// time-ordered, so id-based cursors produce a chronological view without
// needing a separate (timestamp, id) tuple.
//
// Direction:
//   - params.After != "":  rows with id > After, ordered ASC by id (newer page).
//   - params.Before != "" or default: rows with id < Before (or unbounded),
//     ordered DESC by id (older page).
//
// Caller writes statement_timeout — search is best-effort; an admin
// asking for a too-wide window may legitimately fail and that's okay.
func (d *DB) SearchContainerLogs(ctx context.Context, params ContainerSearchParams) ([]ContainerLogRow, error) {
	limit := params.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 5000 {
		limit = 5000
	}

	// Manual $N builder — we need fine-grained index control because
	// search params mix exact-match, range, and JSONB containment.
	var conds []string
	args := []any{}
	var sb strings.Builder
	idx := 0
	push := func(v any) string {
		idx++
		args = append(args, v)
		return fmt.Sprintf("$%d", idx)
	}

	if params.ContainerID != "" {
		conds = append(conds, "container_id = "+push(params.ContainerID))
	}
	if params.ContainerName != "" {
		conds = append(conds, "container_name = "+push(params.ContainerName))
	}
	if params.Project != "" {
		conds = append(conds, "project = "+push(params.Project))
	}
	if params.Component != "" {
		conds = append(conds, "component = "+push(params.Component))
	}
	if params.ReleaseID != "" {
		conds = append(conds, "release_id = "+push(params.ReleaseID))
	}
	if params.DeploymentID != "" {
		if u, err := uuid.Parse(params.DeploymentID); err == nil {
			conds = append(conds, "deployment_id = "+push(u))
		}
	}
	if params.HostID != "" {
		conds = append(conds, "host_id = "+push(params.HostID))
	}
	if s := strings.ToLower(strings.TrimSpace(params.Stream)); s == "stdout" || s == "stderr" {
		conds = append(conds, "stream = "+push(s))
	}
	if !params.From.IsZero() {
		conds = append(conds, "timestamp >= "+push(params.From))
	}
	if !params.To.IsZero() {
		conds = append(conds, "timestamp <= "+push(params.To))
	}
	if q := strings.TrimSpace(params.Query); q != "" {
		if params.Regex {
			conds = append(conds, "line ~ "+push(q))
		} else {
			conds = append(conds, "line ILIKE "+push("%"+q+"%"))
		}
	}
	if len(params.Attrs) > 0 {
		// JSONB containment — single $N for the whole map keeps the
		// jsonb_path_ops index hit clean.
		b, err := json.Marshal(params.Attrs)
		if err == nil {
			conds = append(conds, "attrs @> "+push(json.RawMessage(b))+"::jsonb")
		}
	}

	direction := "DESC"
	if params.After != "" {
		if u, err := uuid.Parse(params.After); err == nil {
			conds = append(conds, "id > "+push(u))
			direction = "ASC"
		}
	} else if params.Before != "" {
		if u, err := uuid.Parse(params.Before); err == nil {
			conds = append(conds, "id < "+push(u))
		}
	}

	sb.WriteString("SELECT")
	sb.WriteString(containerLogSelectCols)
	sb.WriteString(" FROM container_logs")
	if len(conds) > 0 {
		sb.WriteString(" WHERE ")
		sb.WriteString(strings.Join(conds, " AND "))
	}
	sb.WriteString(" ORDER BY id ")
	sb.WriteString(direction)
	sb.WriteString(" LIMIT ")
	sb.WriteString(fmt.Sprint(limit))

	rows, err := d.Pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("search container_logs: %w", err)
	}
	defer rows.Close()

	out := make([]ContainerLogRow, 0, limit)
	for rows.Next() {
		var r ContainerLogRow
		var attrs []byte
		var deployIDPtr *string
		if err := rows.Scan(
			&r.ID, &r.Timestamp, &r.ReceivedAt, &r.HostID, &r.ContainerID, &r.ContainerName,
			&r.Image, &r.Project, &r.Component, &r.ReleaseID, &deployIDPtr, &r.Stream, &r.Line,
			&r.Truncated, &r.Seq, &attrs,
		); err != nil {
			return nil, fmt.Errorf("scan container_log: %w", err)
		}
		r.DeploymentID = deployIDPtr
		if len(attrs) > 0 {
			r.Attrs = json.RawMessage(attrs)
		}
		out = append(out, r)
	}

	// Restore chronological order when paginating ASC so the caller
	// always renders newest-first regardless of direction.
	if direction == "ASC" {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	return out, rows.Err()
}

// GetContainerLogContext returns up to N rows older AND N rows newer than
// the anchor id, all from the same container, plus the anchor itself. The
// UI uses this for the "view ±50 lines around this hit" surface.
func (d *DB) GetContainerLogContext(ctx context.Context, anchorID string, n int) ([]ContainerLogRow, error) {
	if n <= 0 {
		n = 50
	}
	if n > 500 {
		n = 500
	}
	anchorUUID, err := uuid.Parse(anchorID)
	if err != nil {
		return nil, fmt.Errorf("invalid anchor id: %w", err)
	}

	// First fetch the anchor to learn container_id + timestamp window.
	var containerID string
	var anchorTS time.Time
	if err := d.Pool.QueryRow(ctx,
		`SELECT container_id, timestamp FROM container_logs WHERE id = $1 LIMIT 1`,
		anchorUUID,
	).Scan(&containerID, &anchorTS); err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("anchor not found")
		}
		return nil, fmt.Errorf("anchor lookup: %w", err)
	}

	// Window the timestamp filter to keep the planner away from full
	// chunk scans — ±2 hours is generous for a context view but bounds
	// the search.
	tsMin := anchorTS.Add(-2 * time.Hour)
	tsMax := anchorTS.Add(2 * time.Hour)

	q := `
WITH older AS (
    SELECT ` + containerLogSelectCols + `
    FROM container_logs
    WHERE container_id = $1
      AND timestamp BETWEEN $2 AND $3
      AND id < $4
    ORDER BY id DESC
    LIMIT $5
),
anchor AS (
    SELECT ` + containerLogSelectCols + `
    FROM container_logs
    WHERE id = $4
),
newer AS (
    SELECT ` + containerLogSelectCols + `
    FROM container_logs
    WHERE container_id = $1
      AND timestamp BETWEEN $2 AND $3
      AND id > $4
    ORDER BY id ASC
    LIMIT $5
)
SELECT * FROM older
UNION ALL
SELECT * FROM anchor
UNION ALL
SELECT * FROM newer
ORDER BY id ASC`

	rows, err := d.Pool.Query(ctx, q, containerID, tsMin, tsMax, anchorUUID, n)
	if err != nil {
		return nil, fmt.Errorf("context query: %w", err)
	}
	defer rows.Close()

	out := make([]ContainerLogRow, 0, 2*n+1)
	for rows.Next() {
		var r ContainerLogRow
		var attrs []byte
		var deployIDPtr *string
		if err := rows.Scan(
			&r.ID, &r.Timestamp, &r.ReceivedAt, &r.HostID, &r.ContainerID, &r.ContainerName,
			&r.Image, &r.Project, &r.Component, &r.ReleaseID, &deployIDPtr, &r.Stream, &r.Line,
			&r.Truncated, &r.Seq, &attrs,
		); err != nil {
			return nil, fmt.Errorf("scan context row: %w", err)
		}
		r.DeploymentID = deployIDPtr
		if len(attrs) > 0 {
			r.Attrs = json.RawMessage(attrs)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ContainerRow mirrors a row from the dimension table.
type ContainerRow struct {
	ID            string          `json:"id"`
	ContainerID   string          `json:"container_id"`
	ContainerName string          `json:"container_name"`
	Image         string          `json:"image"`
	ImageDigest   string          `json:"image_digest"`
	Project       *string         `json:"project,omitempty"`
	Component     *string         `json:"component,omitempty"`
	ReleaseID     *string         `json:"release_id,omitempty"`
	DeploymentID  *string         `json:"deployment_id,omitempty"`
	HostID        string          `json:"host_id"`
	Labels        json.RawMessage `json:"labels,omitempty"`
	StartedAt     time.Time       `json:"started_at"`
	FinishedAt    *time.Time      `json:"finished_at,omitempty"`
	ExitCode      *int            `json:"exit_code,omitempty"`
	LastLogAt     *time.Time      `json:"last_log_at,omitempty"`
}

// ContainerListParams filters the dimension table.
type ContainerListParams struct {
	Project   string
	Component string
	HostID    string
	State     string // "" | "running" | "exited"
	Limit     int
	Before    string // cursor on id
}

// ListContainers returns dimension rows newest-first.
func (d *DB) ListContainers(ctx context.Context, params ContainerListParams) ([]ContainerRow, error) {
	limit := params.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	var conds []string
	args := []any{}
	idx := 0
	push := func(v any) string {
		idx++
		args = append(args, v)
		return fmt.Sprintf("$%d", idx)
	}

	if params.Project != "" {
		conds = append(conds, "project = "+push(params.Project))
	}
	if params.Component != "" {
		conds = append(conds, "component = "+push(params.Component))
	}
	if params.HostID != "" {
		conds = append(conds, "host_id = "+push(params.HostID))
	}
	switch strings.ToLower(strings.TrimSpace(params.State)) {
	case "running":
		conds = append(conds, "finished_at IS NULL")
	case "exited":
		conds = append(conds, "finished_at IS NOT NULL")
	}
	if params.Before != "" {
		if u, err := uuid.Parse(params.Before); err == nil {
			conds = append(conds, "id < "+push(u))
		}
	}

	q := `
SELECT id, container_id, container_name, image, image_digest, project, component,
       release_id, deployment_id::text, host_id, labels, started_at, finished_at,
       exit_code, last_log_at
FROM containers`
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY id DESC LIMIT " + fmt.Sprint(limit)

	rows, err := d.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	defer rows.Close()

	out := make([]ContainerRow, 0, limit)
	for rows.Next() {
		var r ContainerRow
		var labels []byte
		var deployIDPtr *string
		if err := rows.Scan(
			&r.ID, &r.ContainerID, &r.ContainerName, &r.Image, &r.ImageDigest,
			&r.Project, &r.Component, &r.ReleaseID, &deployIDPtr, &r.HostID,
			&labels, &r.StartedAt, &r.FinishedAt, &r.ExitCode, &r.LastLogAt,
		); err != nil {
			return nil, fmt.Errorf("scan container: %w", err)
		}
		r.DeploymentID = deployIDPtr
		if len(labels) > 0 {
			r.Labels = json.RawMessage(labels)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetContainer returns a single dimension row by container_id.
func (d *DB) GetContainer(ctx context.Context, containerID string) (ContainerRow, error) {
	var r ContainerRow
	var labels []byte
	var deployIDPtr *string
	err := d.Pool.QueryRow(ctx, `
SELECT id, container_id, container_name, image, image_digest, project, component,
       release_id, deployment_id::text, host_id, labels, started_at, finished_at,
       exit_code, last_log_at
FROM containers WHERE container_id = $1 LIMIT 1`, containerID).Scan(
		&r.ID, &r.ContainerID, &r.ContainerName, &r.Image, &r.ImageDigest,
		&r.Project, &r.Component, &r.ReleaseID, &deployIDPtr, &r.HostID,
		&labels, &r.StartedAt, &r.FinishedAt, &r.ExitCode, &r.LastLogAt,
	)
	if err != nil {
		return r, err
	}
	r.DeploymentID = deployIDPtr
	if len(labels) > 0 {
		r.Labels = json.RawMessage(labels)
	}
	return r, nil
}

// UpsertContainerInput is the dimension-table upsert payload.
type UpsertContainerInput struct {
	ContainerID   string
	ContainerName string
	Image         string
	ImageDigest   string
	Project       string
	Component     string
	ReleaseID     string
	DeploymentID  string
	HostID        string
	Labels        map[string]string
	StartedAt     time.Time
	FinishedAt    *time.Time
	ExitCode      *int
	LastLogAt     *time.Time
}

// UpsertContainer inserts or updates the dimension row. Idempotent on
// container_id; only mutable fields (last_log_at, finished_at, exit_code,
// labels) are merged on conflict.
func (d *DB) UpsertContainer(ctx context.Context, in UpsertContainerInput) error {
	if in.ContainerID == "" {
		return fmt.Errorf("container_id is required")
	}
	hostID := in.HostID
	if hostID == "" {
		hostID = "central"
	}
	labelsJSON, _ := json.Marshal(in.Labels)
	var deployIDPtr *uuid.UUID
	if in.DeploymentID != "" {
		if u, err := uuid.Parse(in.DeploymentID); err == nil {
			deployIDPtr = &u
		}
	}
	startedAt := in.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	_, err := d.Pool.Exec(ctx, `
INSERT INTO containers (
    container_id, container_name, image, image_digest,
    project, component, release_id, deployment_id, host_id,
    labels, started_at, finished_at, exit_code, last_log_at
) VALUES (
    $1, $2, $3, $4,
    NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), $8, $9,
    $10::jsonb, $11, $12, $13, $14
)
ON CONFLICT (container_id) DO UPDATE SET
    container_name = EXCLUDED.container_name,
    image          = COALESCE(NULLIF(EXCLUDED.image, ''),         containers.image),
    image_digest   = COALESCE(NULLIF(EXCLUDED.image_digest, ''),  containers.image_digest),
    project        = COALESCE(EXCLUDED.project,                   containers.project),
    component      = COALESCE(EXCLUDED.component,                 containers.component),
    release_id     = COALESCE(EXCLUDED.release_id,                containers.release_id),
    deployment_id  = COALESCE(EXCLUDED.deployment_id,             containers.deployment_id),
    host_id        = EXCLUDED.host_id,
    labels         = CASE WHEN EXCLUDED.labels = '{}'::jsonb THEN containers.labels ELSE EXCLUDED.labels END,
    finished_at    = COALESCE(EXCLUDED.finished_at,               containers.finished_at),
    exit_code      = COALESCE(EXCLUDED.exit_code,                 containers.exit_code),
    last_log_at    = COALESCE(EXCLUDED.last_log_at,               containers.last_log_at)`,
		in.ContainerID, in.ContainerName, in.Image, in.ImageDigest,
		in.Project, in.Component, in.ReleaseID, deployIDPtr, hostID,
		string(labelsJSON), startedAt, in.FinishedAt, in.ExitCode, in.LastLogAt,
	)
	if err != nil {
		return fmt.Errorf("upsert container: %w", err)
	}
	return nil
}

// LastLogTimeForContainer returns the timestamp of the latest container_log
// row for the given container, used by the shipper to resume tailing with
// `since=<lastLogAt>` after a restart.
func (d *DB) LastLogTimeForContainer(ctx context.Context, containerID string) (time.Time, error) {
	var ts time.Time
	err := d.Pool.QueryRow(ctx,
		`SELECT timestamp FROM container_logs WHERE container_id = $1 ORDER BY timestamp DESC LIMIT 1`,
		containerID,
	).Scan(&ts)
	if err == pgx.ErrNoRows {
		return time.Time{}, nil
	}
	return ts, err
}
