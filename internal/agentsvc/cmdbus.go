package agentsvc

import (
	"sync"
)

// CommandBus is the in-memory wake channel used to unblock long-poll
// agent connections when a new command lands in muvon.agent_commands.
// It's NOT a transport — the actual command body lives in the DB. The
// bus only carries "wake up and check the queue" signals.
//
// Per-agent design: each agent gets a slice of subscriber channels.
// One agent typically has one active poll connection, but reconnects
// or clock-skew retries can briefly have two; both wake on the same
// notification and race for the DB row via FOR UPDATE SKIP LOCKED.
//
// Why a tiny channel-per-poll instead of a single condition variable:
// channels integrate naturally with select{} so the poll handler can
// race the wake signal against the wait-timeout and ctx.Done() in one
// place. Condition variables would need a separate goroutine to feed
// a channel anyway.
type CommandBus struct {
	mu      sync.Mutex
	clients map[string]map[chan struct{}]struct{}
}

func NewCommandBus() *CommandBus {
	return &CommandBus{clients: make(map[string]map[chan struct{}]struct{})}
}

// Subscribe registers a wake channel for the given agent and returns
// it plus a cancel func the caller MUST call on exit (defer
// unsubscribe(); race-free closing).
func (b *CommandBus) Subscribe(agentID string) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1) // buffer 1 so a notify before subscribe.Recv doesn't get lost
	b.mu.Lock()
	set, ok := b.clients[agentID]
	if !ok {
		set = make(map[chan struct{}]struct{})
		b.clients[agentID] = set
	}
	set[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		if s, ok := b.clients[agentID]; ok {
			delete(s, ch)
			if len(s) == 0 {
				delete(b.clients, agentID)
			}
		}
		b.mu.Unlock()
	}
}

// Wake signals every current subscriber for agentID that a new
// command may be available. Non-blocking: a subscriber that has
// already been woken keeps its single buffered token (idempotent).
func (b *CommandBus) Wake(agentID string) {
	b.mu.Lock()
	subs := b.clients[agentID]
	channels := make([]chan struct{}, 0, len(subs))
	for ch := range subs {
		channels = append(channels, ch)
	}
	b.mu.Unlock()
	for _, ch := range channels {
		select {
		case ch <- struct{}{}:
		default:
			// Already pending — the next select{} pickup will see it.
		}
	}
}
