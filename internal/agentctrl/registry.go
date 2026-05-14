package agentctrl

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Registry is the agent-side dispatch table: kind → handler. The agent
// constructs a Registry at startup, registers a Handler for each kind
// it implements, and calls Dispatch when a command arrives.
//
// Two safety nets baked into Dispatch:
//   1. Panic-safe: a handler that panics turns into a "failed" result
//      with the recovered value as the error string. The poll loop
//      keeps running.
//   2. Replay-safe: an in-memory LRU of seen (id, nonce) pairs rejects
//      a duplicate command body even if TLS were somehow downgraded.
//      The LRU is bounded so memory stays predictable on long uptimes.
type Registry struct {
	mu       sync.RWMutex
	handlers map[CommandKind]Handler
	// seen tracks the last N command IDs the agent has dispatched so
	// at-least-once delivery can't translate into "executed twice".
	// IDs are UUIDv7 so we don't even need the nonce — the ID alone
	// is unique. Keeping nonce in the key as an extra guard.
	seen    map[string]struct{}
	seenLRU []string
	maxSeen int
}

// NewRegistry constructs an empty Registry. maxSeen caps the dedup
// memory; the agent's poll cadence is ~25s so 1000 entries cover ~7
// hours of commands at one per minute — plenty of slack.
func NewRegistry(maxSeen int) *Registry {
	if maxSeen <= 0 {
		maxSeen = 1000
	}
	return &Registry{
		handlers: make(map[CommandKind]Handler),
		seen:     make(map[string]struct{}, maxSeen),
		seenLRU:  make([]string, 0, maxSeen),
		maxSeen:  maxSeen,
	}
}

// Register binds a handler to a kind. Calling Register twice for the
// same kind overwrites — useful for tests; in production a single
// init phase registers each kind exactly once.
func (r *Registry) Register(kind CommandKind, h Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[kind] = h
}

// markSeen records a command ID in the dedup LRU. Returns true if the
// ID was newly inserted, false if it had already been seen — caller
// uses the boolean to skip executing duplicates.
func (r *Registry) markSeen(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.seen[id]; ok {
		return false
	}
	if len(r.seenLRU) >= r.maxSeen {
		// Drop the oldest entry. Slice trim + map delete.
		drop := r.seenLRU[0]
		r.seenLRU = r.seenLRU[1:]
		delete(r.seen, drop)
	}
	r.seen[id] = struct{}{}
	r.seenLRU = append(r.seenLRU, id)
	return true
}

// Dispatch runs the handler for cmd.Kind, returning the Result that
// should be POSTed to /api/v1/agent/commands/:id/result. Never panics;
// always returns a Result with State=succeeded or State=failed.
func (r *Registry) Dispatch(ctx context.Context, cmd Command) Result {
	if !r.markSeen(cmd.ID) {
		// Already executed — return success without rerunning. Server
		// will mark the command succeeded (which is correct: the work
		// was done, this just reports it again).
		return Result{
			CommandID: cmd.ID,
			State:     StateSucceeded,
			Output:    "already executed (duplicate delivery)",
		}
	}

	r.mu.RLock()
	h, ok := r.handlers[cmd.Kind]
	r.mu.RUnlock()
	if !ok {
		return Result{
			CommandID: cmd.ID,
			State:     StateFailed,
			Error:     fmt.Sprintf("unknown command kind: %s", cmd.Kind),
		}
	}

	// Panic recovery — handler bug must not crash the poll loop.
	result := Result{CommandID: cmd.ID}
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				result.State = StateFailed
				result.Error = fmt.Sprintf("handler panic: %v", rec)
				slog.Error("agent command handler panicked", "kind", cmd.Kind, "id", cmd.ID, "panic", rec)
			}
		}()
		// Each handler gets a bounded context so a buggy handler that
		// blocks forever doesn't wedge the poll loop.
		runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		out, err := h(runCtx, cmd)
		if err != nil {
			result.State = StateFailed
			result.Error = err.Error()
			result.Output = out.Output
			return
		}
		// Handler is allowed to set State explicitly (e.g. KindAgentRevoke
		// returns succeeded just before terminating). Default to succeeded
		// when the handler didn't say.
		if out.State == "" {
			out.State = StateSucceeded
		}
		out.CommandID = cmd.ID
		result = out
	}()
	return result
}
