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
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func (d *DB) ListAgents(ctx context.Context) ([]Agent, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT id, name, api_key, is_active, last_seen_at, created_at, updated_at
		 FROM agents ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	defer rows.Close()

	var agents []Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(&a.ID, &a.Name, &a.APIKey, &a.IsActive, &a.LastSeenAt, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("list agents scan: %w", err)
		}
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

func (d *DB) CreateAgent(ctx context.Context, name, apiKey string) (Agent, error) {
	var a Agent
	err := d.Pool.QueryRow(ctx,
		`INSERT INTO agents (id, name, api_key)
		 VALUES (gen_uuidv7()::text, $1, $2)
		 RETURNING id, name, api_key, is_active, last_seen_at, created_at, updated_at`,
		name, apiKey,
	).Scan(&a.ID, &a.Name, &a.APIKey, &a.IsActive, &a.LastSeenAt, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return a, fmt.Errorf("create agent: %w", err)
	}
	return a, nil
}

func (d *DB) TouchAgentLastSeen(ctx context.Context, id string) {
	d.Pool.Exec(ctx, `UPDATE agents SET last_seen_at = now() WHERE id = $1`, id)
}

func (d *DB) GetAgentByKey(ctx context.Context, apiKey string) (Agent, error) {
	var a Agent
	err := d.Pool.QueryRow(ctx,
		`SELECT id, name, api_key, is_active, last_seen_at, created_at, updated_at
		 FROM agents WHERE api_key = $1`,
		apiKey,
	).Scan(&a.ID, &a.Name, &a.APIKey, &a.IsActive, &a.LastSeenAt, &a.CreatedAt, &a.UpdatedAt)
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
