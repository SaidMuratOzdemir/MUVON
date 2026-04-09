package health

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"muvon/internal/config"
)

// State represents a circuit breaker state.
type State int

const (
	Closed   State = iota // Normal operation — requests pass through
	Open                  // Failing — requests rejected immediately
	HalfOpen              // Cooldown elapsed — one probe request allowed
)

func (s State) String() string {
	switch s {
	case Closed:
		return "closed"
	case Open:
		return "open"
	case HalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

const (
	defaultThreshold = 3
	defaultCooldown  = 30 * time.Second
	pingInterval     = 10 * time.Second
	pingTimeout      = 2 * time.Second
)

// CircuitBreaker is a 3-state per-backend circuit breaker.
type CircuitBreaker struct {
	mu          sync.Mutex
	state       State
	failures    int
	threshold   int
	cooldown    time.Duration
	openedAt    time.Time
	backendURL  string
}

func newCircuitBreaker(url string) *CircuitBreaker {
	return &CircuitBreaker{
		backendURL: url,
		state:      Closed,
		threshold:  defaultThreshold,
		cooldown:   defaultCooldown,
	}
}

// Allow returns true if the request should be forwarded to the backend.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case Closed:
		return true
	case HalfOpen:
		return true
	case Open:
		if time.Since(cb.openedAt) >= cb.cooldown {
			cb.state = HalfOpen
			return true
		}
		return false
	}
	return true
}

// RecordSuccess transitions from HalfOpen → Closed and resets failure count.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.state = Closed
}

// RecordFailure increments the failure counter and may trip the breaker.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	if cb.failures >= cb.threshold {
		if cb.state != Open {
			slog.Warn("circuit breaker opened", "backend", cb.backendURL, "failures", cb.failures)
		}
		cb.state = Open
		cb.openedAt = time.Now()
	}
}

// GetState returns the current state without side effects.
func (cb *CircuitBreaker) GetState() State {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.state == Open && time.Since(cb.openedAt) >= cb.cooldown {
		return HalfOpen
	}
	return cb.state
}

// Manager maintains a circuit breaker per backend URL and runs background health pings.
type Manager struct {
	mu       sync.RWMutex
	breakers map[string]*CircuitBreaker
	quit     chan struct{}
	client   *http.Client
}

// NewManager creates a Manager and starts background health pings for the given URLs.
func NewManager() *Manager {
	return &Manager{
		breakers: make(map[string]*CircuitBreaker),
		quit:     make(chan struct{}),
		client: &http.Client{
			Timeout: pingTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Register ensures a circuit breaker exists for the given URL.
func (m *Manager) Register(url string) {
	if url == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.breakers[url]; !ok {
		m.breakers[url] = newCircuitBreaker(url)
	}
}

// SyncBackends registers backends from the given config and removes stale ones.
func (m *Manager) SyncBackends(cfg *config.Config) {
	wanted := make(map[string]bool)
	for _, hc := range cfg.Hosts {
		for _, r := range hc.Routes {
			if r.Route.BackendURL != nil && *r.Route.BackendURL != "" {
				wanted[*r.Route.BackendURL] = true
			}
			for _, u := range r.Route.BackendURLs {
				wanted[u] = true
			}
		}
	}

	m.mu.Lock()
	// Remove stale
	for url := range m.breakers {
		if !wanted[url] {
			delete(m.breakers, url)
		}
	}
	// Add new
	for url := range wanted {
		if _, ok := m.breakers[url]; !ok {
			m.breakers[url] = newCircuitBreaker(url)
		}
	}
	m.mu.Unlock()
}

// Allow returns true if the circuit is closed or half-open for the given backend URL.
func (m *Manager) Allow(url string) bool {
	m.mu.RLock()
	cb, ok := m.breakers[url]
	m.mu.RUnlock()
	if !ok {
		return true
	}
	return cb.Allow()
}

// RecordSuccess records a successful upstream call.
func (m *Manager) RecordSuccess(url string) {
	m.mu.RLock()
	cb, ok := m.breakers[url]
	m.mu.RUnlock()
	if ok {
		cb.RecordSuccess()
	}
}

// RecordFailure records a failed upstream call.
func (m *Manager) RecordFailure(url string) {
	m.mu.RLock()
	cb, ok := m.breakers[url]
	m.mu.RUnlock()
	if ok {
		cb.RecordFailure()
	}
}

// GetAll returns a snapshot of all backend states as strings.
func (m *Manager) GetAll() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]string, len(m.breakers))
	for url, cb := range m.breakers {
		out[url] = cb.GetState().String()
	}
	return out
}

// Start runs background health pings until Stop is called.
func (m *Manager) Start() {
	go m.pingLoop()
}

// Stop shuts down the background ping loop.
func (m *Manager) Stop() {
	close(m.quit)
}

func (m *Manager) pingLoop() {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.quit:
			return
		case <-ticker.C:
			m.pingAll()
		}
	}
}

func (m *Manager) pingAll() {
	m.mu.RLock()
	urls := make([]string, 0, len(m.breakers))
	for url := range m.breakers {
		urls = append(urls, url)
	}
	m.mu.RUnlock()

	for _, url := range urls {
		go m.ping(url)
	}
}

func (m *Manager) ping(rawURL string) {
	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "dialog-healthcheck/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		m.RecordFailure(rawURL)
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 500 {
		m.RecordFailure(rawURL)
	} else {
		m.RecordSuccess(rawURL)
	}
}
