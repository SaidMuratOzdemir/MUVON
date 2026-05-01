package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Agent represents a registered remote agent (client server).
type Agent struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	APIKey      string     `json:"api_key"`
	IsActive    bool       `json:"is_active"`
	LastSeenAt  *time.Time `json:"last_seen_at"`
	// Observability — populated whenever the agent pulls config or
	// reconnects to the SSE watch stream. Used by the admin UI to flag
	// agents that are alive but lagging behind the current config.
	LastConfigPullAt *time.Time `json:"last_config_pull_at"`
	ConfigVersion    string     `json:"config_version"`
	LastRemoteAddr   string     `json:"last_remote_addr"`
	LastUserAgent    string     `json:"last_user_agent"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

const agentSelectCols = `id, name, api_key, is_active, last_seen_at,
	last_config_pull_at, config_version, last_remote_addr, last_user_agent,
	created_at, updated_at`

func scanAgent(scan func(...any) error) (Agent, error) {
	var a Agent
	err := scan(&a.ID, &a.Name, &a.APIKey, &a.IsActive, &a.LastSeenAt,
		&a.LastConfigPullAt, &a.ConfigVersion, &a.LastRemoteAddr, &a.LastUserAgent,
		&a.CreatedAt, &a.UpdatedAt)
	return a, err
}

func (d *DB) ListAgents(ctx context.Context) ([]Agent, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT `+agentSelectCols+` FROM agents ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	defer rows.Close()

	var agents []Agent
	for rows.Next() {
		a, err := scanAgent(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("list agents scan: %w", err)
		}
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

func (d *DB) CreateAgent(ctx context.Context, name, apiKey string) (Agent, error) {
	a, err := scanAgent(d.Pool.QueryRow(ctx,
		`INSERT INTO agents (id, name, api_key)
		 VALUES (gen_uuidv7()::text, $1, $2)
		 RETURNING `+agentSelectCols,
		name, apiKey,
	).Scan)
	if err != nil {
		return a, fmt.Errorf("create agent: %w", err)
	}
	return a, nil
}

func (d *DB) TouchAgentLastSeen(ctx context.Context, id string) {
	d.Pool.Exec(ctx, `UPDATE agents SET last_seen_at = now() WHERE id = $1`, id)
}

// RecordAgentConfigPull stamps the agent row with the latest config it pulled.
// Called whenever the agent hits /api/v1/agent/config so the admin UI can
// distinguish "alive on the SSE channel" from "actually applied recent config".
func (d *DB) RecordAgentConfigPull(ctx context.Context, id, version, remoteAddr, userAgent string) {
	d.Pool.Exec(ctx,
		`UPDATE agents
		 SET last_seen_at = now(),
		     last_config_pull_at = now(),
		     config_version = $2,
		     last_remote_addr = $3,
		     last_user_agent = $4
		 WHERE id = $1`,
		id, version, remoteAddr, userAgent)
}

func (d *DB) GetAgentByKey(ctx context.Context, apiKey string) (Agent, error) {
	a, err := scanAgent(d.Pool.QueryRow(ctx,
		`SELECT `+agentSelectCols+` FROM agents WHERE api_key = $1`,
		apiKey,
	).Scan)
	if err != nil {
		return a, fmt.Errorf("get agent by key: %w", err)
	}
	return a, nil
}

func (d *DB) DeleteAgent(ctx context.Context, id string) error {
	ct, err := d.Pool.Exec(ctx, `DELETE FROM agents WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete agent: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ValidateAgentKey returns true if the given API key belongs to an active agent.
func (d *DB) ValidateAgentKey(ctx context.Context, apiKey string) (bool, error) {
	var isActive bool
	err := d.Pool.QueryRow(ctx,
		`SELECT is_active FROM agents WHERE api_key = $1`, apiKey,
	).Scan(&isActive)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return isActive, nil
}
