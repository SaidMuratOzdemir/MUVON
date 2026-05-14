package agentsvc

import "sync"

// Broadcaster notifies all connected SSE agent clients when config changes.
type Broadcaster struct {
	mu      sync.Mutex
	clients map[chan struct{}]struct{}
}

func NewBroadcaster() *Broadcaster {
	return &Broadcaster{clients: make(map[chan struct{}]struct{})}
}

func (b *Broadcaster) Subscribe() chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan struct{}, 1)
	b.clients[ch] = struct{}{}
	return ch
}

func (b *Broadcaster) Unsubscribe(ch chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.clients, ch)
}

// Broadcast signals all connected agents that config has changed.
func (b *Broadcaster) Broadcast() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.clients {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
