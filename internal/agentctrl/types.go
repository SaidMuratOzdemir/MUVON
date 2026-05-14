// Package agentctrl defines the command/control protocol between the
// central admin server and edge agents. It is transport-agnostic by
// design — the same types feed both the HTTP long-poll endpoint shipped
// today and a possible future gRPC bidi stream.
//
// Architecture in one paragraph:
//
//   The central admin server enqueues commands as rows in
//   muvon.agent_commands (Postgres). Each command carries an HMAC
//   signature so the receiving agent can verify it came from a peer
//   that holds the shared encryption key. The agent runs a long-poll
//   loop hitting GET /api/v1/agent/commands; the server wakes pending
//   polls via an in-memory per-agent bus when a new row arrives. The
//   agent dispatches the command through a Registry of idempotent
//   handlers, then POSTs the Result back. State transitions are
//   pending → dispatched → succeeded|failed, with a sweeper marking
//   stale rows as expired.
//
// Why a separate package: the types are used by three call sites —
// the admin HTTP handlers, the agent's poll loop, and the Postgres
// query layer — and putting them in any of those packages would
// create import cycles or coupling.
package agentctrl

import (
	"context"
	"encoding/json"
	"time"
)

// CommandKind enumerates every operation an operator can trigger.
// New kinds MUST be added to this list and to the Registry's default
// handlers (or rejected explicitly on the agent side). Unknown kinds
// must fail closed — the agent reports "unknown command kind" rather
// than silently ignoring.
type CommandKind string

const (
	// KindAgentSelfUpgrade tells the agent to docker-pull a newer
	// image and restart itself. Payload: {"image": "ghcr.io/...:vX"}.
	KindAgentSelfUpgrade CommandKind = "agent.self_upgrade"

	// KindAgentRestart restarts the agent process by terminating
	// itself; Docker's restart policy brings it back. No payload.
	KindAgentRestart CommandKind = "agent.restart"

	// KindAgentDrain stops accepting new connections; existing ones
	// finish naturally. Payload: {"enabled": true|false}.
	KindAgentDrain CommandKind = "agent.drain"

	// KindAgentCacheFlush invalidates local TLS / config caches.
	// Payload: {"target": "config"|"cert"|"all"}.
	KindAgentCacheFlush CommandKind = "agent.cache_flush"

	// KindAgentSetLogLevel changes slog level at runtime with a TTL.
	// Payload: {"level": "debug"|"info"|"warn"|"error", "ttl_seconds": int}.
	// After ttl_seconds elapses the agent reverts to "info".
	KindAgentSetLogLevel CommandKind = "agent.set_log_level"

	// KindCertRenew forces ACME renewal for the named domain even if
	// the existing cert hasn't reached its 30-day window. Payload:
	// {"domain": "..."}.
	KindCertRenew CommandKind = "cert.renew"

	// KindContainerRestart restarts a managed component's container.
	// Payload: {"instance_id": "<uuid>"}.
	KindContainerRestart CommandKind = "container.restart"

	// KindDeployAbort cancels a running deployment if it hasn't yet
	// reached "promoted". Payload: {"deployment_id": "<uuid>"}.
	KindDeployAbort CommandKind = "deploy.abort"

	// KindAgentRevoke is terminal — the agent acknowledges, then
	// exits with a non-zero code so Docker's restart policy doesn't
	// bounce it. No payload.
	KindAgentRevoke CommandKind = "agent.revoke"
)

// AllKinds is the master list for handler registration sanity checks
// and admin UI dropdowns. Order matches the operator-facing severity
// (least-destructive first).
var AllKinds = []CommandKind{
	KindAgentCacheFlush,
	KindAgentSetLogLevel,
	KindCertRenew,
	KindContainerRestart,
	KindAgentDrain,
	KindDeployAbort,
	KindAgentRestart,
	KindAgentSelfUpgrade,
	KindAgentRevoke,
}

// State is the lifecycle of an agent command.
type State string

const (
	StatePending    State = "pending"    // queued, not yet claimed
	StateDispatched State = "dispatched" // claimed by agent, executing
	StateSucceeded  State = "succeeded"  // terminal, ok
	StateFailed     State = "failed"     // terminal, error
	StateExpired    State = "expired"    // terminal, never delivered or never finished
)

// Command is what travels server → agent. Signature covers every
// other field so the agent can reject anything that didn't come
// through the central's signing path (defence against a compromised
// admin DB connection that an attacker bypassed the API layer with).
type Command struct {
	ID        string          `json:"id"`         // UUIDv7, hex
	Kind      CommandKind     `json:"kind"`
	Payload   json.RawMessage `json:"payload"`    // schema-per-kind
	ExpiresAt time.Time       `json:"expires_at"` // RFC3339 on the wire
	Nonce     []byte          `json:"nonce"`      // 16 random bytes
	Signature []byte          `json:"signature"`  // HMAC-SHA256 over (id|kind|payload|expires_at|nonce)
}

// Result is what travels agent → server when a command completes.
// State is one of the terminal States. Output is human-readable text
// surfaced in the operator UI; Data is a kind-specific blob (e.g. the
// new image digest after agent.self_upgrade).
type Result struct {
	CommandID string          `json:"command_id"`
	State     State           `json:"state"` // succeeded | failed
	Output    string          `json:"output,omitempty"`
	Error     string          `json:"error,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
}

// Handler is the contract every command kind must implement on the
// agent side. Handlers MUST be idempotent: receiving the same command
// twice (e.g. because the agent crashed between executing and
// reporting) must not double-apply. Handlers SHOULD bound their own
// execution time and respect ctx cancellation.
type Handler func(ctx context.Context, cmd Command) (Result, error)
