package agentsvc

import (
	"context"
	"sync"
	"time"
)

// sessions tracks the agent requests in flight so that revoking, rotating or
// deleting an agent can end them. Every agent request authenticates on
// arrival, but the config watch stream and the command long poll outlive the
// check that admitted them.
type sessions struct {
	mu     sync.Mutex
	next   uint64
	open   map[string]map[uint64]context.CancelFunc
	closed map[string]time.Time
}

// start registers a request admitted at admittedAt. A request whose key was
// looked up before the agent was closed gets an already cancelled context:
// its lookup may have read the row before the revocation committed.
func (s *sessions) start(parent context.Context, agentID string, admittedAt time.Time) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	s.mu.Lock()
	if closedAt, ok := s.closed[agentID]; ok && !admittedAt.After(closedAt) {
		s.mu.Unlock()
		cancel()
		return ctx, func() {}
	}
	if s.open == nil {
		s.open = make(map[string]map[uint64]context.CancelFunc)
	}
	if s.open[agentID] == nil {
		s.open[agentID] = make(map[uint64]context.CancelFunc)
	}
	s.next++
	n := s.next
	s.open[agentID][n] = cancel
	s.mu.Unlock()

	return ctx, func() {
		s.mu.Lock()
		delete(s.open[agentID], n)
		if len(s.open[agentID]) == 0 {
			delete(s.open, agentID)
		}
		s.mu.Unlock()
		cancel()
	}
}

// close ends every request of an agent and refuses those admitted before now.
// It returns how many were open.
func (s *sessions) close(agentID string) int {
	s.mu.Lock()
	if s.closed == nil {
		s.closed = make(map[string]time.Time)
	}
	s.closed[agentID] = time.Now()
	running := s.open[agentID]
	delete(s.open, agentID)
	s.mu.Unlock()

	for _, cancel := range running {
		cancel()
	}
	return len(running)
}
