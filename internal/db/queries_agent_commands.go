package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// AgentCommand mirrors the muvon.agent_commands row. Kept thin and
// flat so the admin / agent / sweeper handlers can scan it directly.
type AgentCommand struct {
	ID           string          `json:"id"`
	AgentID      string          `json:"agent_id"`
	Kind         string          `json:"kind"`
	Payload      json.RawMessage `json:"payload"`
	State        string          `json:"state"`
	CreatedAt    time.Time       `json:"created_at"`
	DispatchedAt *time.Time      `json:"dispatched_at,omitempty"`
	FinishedAt   *time.Time      `json:"finished_at,omitempty"`
	ExpiresAt    time.Time       `json:"expires_at"`
	Result       json.RawMessage `json:"result,omitempty"`
	IssuedBy     string          `json:"issued_by"`
	// Nonce + Signature are sent to the agent but redacted from
	// admin-facing responses — they're internal to the protocol.
	Nonce     []byte `json:"nonce,omitempty"`
	Signature []byte `json:"signature,omitempty"`
}

const agentCommandSelectCols = `id::text, agent_id, kind, payload, state,
	created_at, dispatched_at, finished_at, expires_at, result, issued_by,
	nonce, signature`

func scanAgentCommand(scan func(...any) error) (AgentCommand, error) {
	var c AgentCommand
	err := scan(
		&c.ID, &c.AgentID, &c.Kind, &c.Payload, &c.State,
		&c.CreatedAt, &c.DispatchedAt, &c.FinishedAt, &c.ExpiresAt,
		&c.Result, &c.IssuedBy, &c.Nonce, &c.Signature,
	)
	return c, err
}

// EnqueueAgentCommandInput is what the admin handler hands the DB
// layer after signing. ID is generated server-side via gen_uuidv7().
// (Passing nil ID instructs the DB to fill it, mirroring deploy_
// releases / deploy_instances.)
type EnqueueAgentCommandInput struct {
	AgentID   string
	Kind      string
	Payload   json.RawMessage
	ExpiresAt time.Time
	Nonce     []byte
	Signature []byte
	IssuedBy  string
}

// EnqueueAgentCommand inserts a new pending command. Returns the row
// with its server-generated ID + timestamps so the admin handler can
// echo it (without nonce/signature) to the operator UI.
func (d *DB) EnqueueAgentCommand(ctx context.Context, in EnqueueAgentCommandInput) (AgentCommand, error) {
	if in.AgentID == "" {
		return AgentCommand{}, errors.New("enqueue agent command: agent_id required")
	}
	if in.Kind == "" {
		return AgentCommand{}, errors.New("enqueue agent command: kind required")
	}
	if in.ExpiresAt.IsZero() {
		in.ExpiresAt = time.Now().Add(5 * time.Minute)
	}
	if len(in.Payload) == 0 {
		in.Payload = json.RawMessage(`{}`)
	}
	if in.IssuedBy == "" {
		in.IssuedBy = "system"
	}
	c, err := scanAgentCommand(d.Pool.QueryRow(ctx,
		`INSERT INTO agent_commands (agent_id, kind, payload, expires_at, nonce, signature, issued_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING `+agentCommandSelectCols,
		in.AgentID, in.Kind, in.Payload, in.ExpiresAt, in.Nonce, in.Signature, in.IssuedBy,
	).Scan)
	if err != nil {
		return c, fmt.Errorf("enqueue agent command: %w", err)
	}
	return c, nil
}

// ClaimNextAgentCommand atomically picks the oldest pending command
// for the given agent and flips it to 'dispatched'. The
// FOR UPDATE SKIP LOCKED clause makes two concurrent polls from the
// same agent (e.g. during reconnect) safe — only one of them gets the
// row.
func (d *DB) ClaimNextAgentCommand(ctx context.Context, agentID string) (AgentCommand, bool, error) {
	c, err := scanAgentCommand(d.Pool.QueryRow(ctx,
		`UPDATE agent_commands
		 SET state = 'dispatched', dispatched_at = now()
		 WHERE id = (
		     SELECT id FROM agent_commands
		     WHERE agent_id = $1 AND state = 'pending' AND expires_at > now()
		     ORDER BY id
		     LIMIT 1
		     FOR UPDATE SKIP LOCKED
		 )
		 RETURNING `+agentCommandSelectCols, agentID).Scan)
	if err == pgx.ErrNoRows {
		return c, false, nil
	}
	if err != nil {
		return c, false, fmt.Errorf("claim agent command: %w", err)
	}
	return c, true, nil
}

// FinishAgentCommand stamps a command terminal. Caller passes 'succeeded'
// or 'failed' depending on the agent's reported Result. Returns an
// error if the row was already terminal or doesn't exist — protects
// against late-arriving duplicate results.
func (d *DB) FinishAgentCommand(ctx context.Context, agentID, id, state string, result json.RawMessage) error {
	if state != "succeeded" && state != "failed" {
		return fmt.Errorf("finish agent command: invalid state %q", state)
	}
	tag, err := d.Pool.Exec(ctx,
		`UPDATE agent_commands
		 SET state = $3, finished_at = now(), result = $4
		 WHERE id = $2 AND agent_id = $1 AND state IN ('dispatched','pending')`,
		agentID, id, state, result)
	if err != nil {
		return fmt.Errorf("finish agent command: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("finish agent command: row not found or already terminal")
	}
	return nil
}

// ResetStaleAgentCommands flips commands stuck in 'pending' or
// 'dispatched' past their expires_at to 'expired'. Runs from a sweeper
// goroutine every 30s. Returns the count for observability.
func (d *DB) ResetStaleAgentCommands(ctx context.Context) (int, error) {
	tag, err := d.Pool.Exec(ctx,
		`UPDATE agent_commands
		 SET state = 'expired', finished_at = now()
		 WHERE state IN ('pending','dispatched') AND expires_at < now()`)
	if err != nil {
		return 0, fmt.Errorf("reset stale agent commands: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// ListAgentCommands returns the most recent commands for an agent —
// admin UI history view. Includes terminal states.
func (d *DB) ListAgentCommands(ctx context.Context, agentID string, limit int) ([]AgentCommand, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := d.Pool.Query(ctx,
		`SELECT `+agentCommandSelectCols+`
		 FROM agent_commands
		 WHERE agent_id = $1
		 ORDER BY id DESC
		 LIMIT $2`, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("list agent commands: %w", err)
	}
	defer rows.Close()

	var out []AgentCommand
	for rows.Next() {
		c, err := scanAgentCommand(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("list agent commands scan: %w", err)
		}
		// Strip sensitive fields from admin-facing list.
		c.Nonce = nil
		c.Signature = nil
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateAgentCommandSignature stores the HMAC signature for a freshly
// enqueued row. We sign AFTER the INSERT so the signing input can use
// the server-generated UUIDv7 — operators don't pick command IDs.
func (d *DB) UpdateAgentCommandSignature(ctx context.Context, id string, signature []byte) error {
	tag, err := d.Pool.Exec(ctx,
		`UPDATE agent_commands SET signature = $2 WHERE id = $1`, id, signature)
	if err != nil {
		return fmt.Errorf("update command signature: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("update command signature: row not found")
	}
	return nil
}

// GetAgentCommand fetches a single command by id, scoped to the
// requesting agent (so an attacker who guesses a UUID can't pull
// another agent's command body). Admin queries use the dedicated
// admin-side path without the agent scope.
func (d *DB) GetAgentCommandForAgent(ctx context.Context, agentID, id string) (AgentCommand, error) {
	c, err := scanAgentCommand(d.Pool.QueryRow(ctx,
		`SELECT `+agentCommandSelectCols+`
		 FROM agent_commands
		 WHERE id = $1 AND agent_id = $2`, id, agentID).Scan)
	if err != nil {
		return c, fmt.Errorf("get agent command: %w", err)
	}
	return c, nil
}
