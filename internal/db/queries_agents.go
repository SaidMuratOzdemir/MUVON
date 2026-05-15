package db

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Agent represents a registered remote agent (client server).
type Agent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// APIKey is the legacy plaintext column. It still exists for the
	// transition window — auth path now matches on api_key_hash, but
	// rows created before the hash migration carry only the plaintext
	// until first successful auth back-fills the hash. NEVER serialise
	// over the API: response handlers explicitly omit it.
	APIKey     string     `json:"-"`
	IsActive   bool       `json:"is_active"`
	LastSeenAt *time.Time `json:"last_seen_at"`
	// Observability — populated whenever the agent pulls config or
	// reconnects to the SSE watch stream. Used by the admin UI to flag
	// agents that are alive but lagging behind the current config.
	LastConfigPullAt *time.Time `json:"last_config_pull_at"`
	ConfigVersion    string     `json:"config_version"`
	LastRemoteAddr   string     `json:"last_remote_addr"`
	LastUserAgent    string     `json:"last_user_agent"`
	// PublicIP is what the agent reports as its externally-reachable IP —
	// either auto-detected by install-agent.sh (curl ifconfig.me) or set
	// by the operator with --public-ip. This is the value the admin UI
	// uses when telling the operator what to point DNS at, because
	// LastRemoteAddr in private-network topologies is the agent's
	// private interface and useless for DNS verification.
	PublicIP         string     `json:"public_ip"`
	// ExtraMounts are operator-defined host paths the agent should bind
	// read-only into its container so the embedded deployer can read
	// env files / managed-component mount sources sitting anywhere on
	// the host filesystem. UI-managed; agent picks the list up on every
	// config pull and applies it via agent.self_upgrade.
	ExtraMounts      []string   `json:"extra_mounts"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// hashAPIKey returns the SHA-256 digest used for api_key_hash lookups.
// SHA-256 is sufficient for a 32-byte random secret — the goal is to
// hide plaintext at rest, not slow brute-force of a low-entropy key.
func hashAPIKey(key string) []byte {
	h := sha256.Sum256([]byte(key))
	return h[:]
}

const agentSelectCols = `id, name, api_key, is_active, last_seen_at,
	last_config_pull_at, config_version, last_remote_addr, last_user_agent,
	public_ip, extra_mounts, created_at, updated_at`

func scanAgent(scan func(...any) error) (Agent, error) {
	var a Agent
	var extra []string
	err := scan(&a.ID, &a.Name, &a.APIKey, &a.IsActive, &a.LastSeenAt,
		&a.LastConfigPullAt, &a.ConfigVersion, &a.LastRemoteAddr, &a.LastUserAgent,
		&a.PublicIP, &extra, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return a, err
	}
	if extra == nil {
		extra = []string{}
	}
	a.ExtraMounts = extra
	return a, nil
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
	// Persist both the plaintext (for backwards compatibility while we
	// transition) and the hash (used by the indexed auth lookup).
	a, err := scanAgent(d.Pool.QueryRow(ctx,
		`INSERT INTO agents (id, name, api_key, api_key_hash)
		 VALUES (gen_uuidv7()::text, $1, $2, $3)
		 RETURNING `+agentSelectCols,
		name, apiKey, hashAPIKey(apiKey),
	).Scan)
	if err != nil {
		return a, fmt.Errorf("create agent: %w", err)
	}
	// Hand the plaintext back exactly once to the handler so it can
	// return it to the operator. The struct field is JSON-ignored, so
	// later reads (ListAgents) will never expose it again.
	a.APIKey = apiKey
	return a, nil
}

func (d *DB) TouchAgentLastSeen(ctx context.Context, id string) {
	d.Pool.Exec(ctx, `UPDATE agents SET last_seen_at = now() WHERE id = $1`, id)
}

// RecordAgentConfigPull stamps the agent row with the latest config it pulled.
// Called whenever the agent hits /api/v1/agent/config so the admin UI can
// distinguish "alive on the SSE channel" from "actually applied recent config".
// publicIP is the agent's self-reported externally-reachable IP; empty string
// leaves the existing column value alone (so a transient detection failure
// doesn't blank a previously-known good value).
func (d *DB) RecordAgentConfigPull(ctx context.Context, id, version, remoteAddr, userAgent, publicIP string) {
	d.Pool.Exec(ctx,
		`UPDATE agents
		 SET last_seen_at = now(),
		     last_config_pull_at = now(),
		     config_version = $2,
		     last_remote_addr = $3,
		     last_user_agent = $4,
		     public_ip = CASE WHEN $5 <> '' THEN $5 ELSE public_ip END
		 WHERE id = $1`,
		id, version, remoteAddr, userAgent, publicIP)
}

func (d *DB) GetAgentByKey(ctx context.Context, apiKey string) (Agent, error) {
	hash := hashAPIKey(apiKey)
	// Indexed lookup on the hash column — this is the fast path for any
	// agent that has authenticated at least once since the migration.
	a, err := scanAgent(d.Pool.QueryRow(ctx,
		`SELECT `+agentSelectCols+` FROM agents WHERE api_key_hash = $1`,
		hash,
	).Scan)
	if err == nil {
		return a, nil
	}
	if err != pgx.ErrNoRows {
		return a, fmt.Errorf("get agent by key (hash): %w", err)
	}
	// Lazy migration: any row whose hash column is still NULL (pre-
	// migration data) is matched on the plaintext column once; we
	// back-fill the hash so the next call uses the fast path. Rows that
	// already have a hash but don't match it MUST NOT fall through here
	// — that would re-enable the plaintext-lookup vector.
	a, err = scanAgent(d.Pool.QueryRow(ctx,
		`SELECT `+agentSelectCols+`
		   FROM agents
		  WHERE api_key = $1 AND api_key_hash IS NULL`,
		apiKey,
	).Scan)
	if err != nil {
		return a, fmt.Errorf("get agent by key: %w", err)
	}
	_, _ = d.Pool.Exec(ctx,
		`UPDATE agents SET api_key_hash = $2 WHERE id = $1 AND api_key_hash IS NULL`,
		a.ID, hash)
	return a, nil
}

// GetAgent fetches an agent row by ID. Used by the admin enqueue
// handler to validate the target exists and is active before writing
// a command row.
func (d *DB) GetAgent(ctx context.Context, id string) (Agent, error) {
	a, err := scanAgent(d.Pool.QueryRow(ctx,
		`SELECT `+agentSelectCols+` FROM agents WHERE id = $1`, id,
	).Scan)
	if err != nil {
		return a, fmt.Errorf("get agent: %w", err)
	}
	return a, nil
}

// UpdateAgentExtraMounts replaces the operator-managed bind-mount list
// for an agent. The agent picks up the new list on its next config pull;
// applying the mounts to the live container requires a subsequent
// agent.self_upgrade (which rewrites compose and recreates).
func (d *DB) UpdateAgentExtraMounts(ctx context.Context, id string, mounts []string) error {
	if mounts == nil {
		mounts = []string{}
	}
	tag, err := d.Pool.Exec(ctx,
		`UPDATE agents SET extra_mounts = $2, updated_at = now() WHERE id = $1`,
		id, mounts)
	if err != nil {
		return fmt.Errorf("update agent extra_mounts: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
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

// ValidateAgentKey returns true if the given API key belongs to an active
// agent. Composed on top of GetAgentByKey so the legacy plaintext fallback
// and hash back-fill both kick in here too.
func (d *DB) ValidateAgentKey(ctx context.Context, apiKey string) (bool, error) {
	a, err := d.GetAgentByKey(ctx, apiKey)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return a.IsActive, nil
}
