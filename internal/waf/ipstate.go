package waf

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"muvon/internal/db"
)

// IPStateManager manages in-memory IP state with background persistence to PostgreSQL.
type IPStateManager struct {
	mu       sync.RWMutex
	states   map[string]*IPState
	database *db.DB
	quit     chan struct{}
	wg       sync.WaitGroup
}

// NewIPStateManager creates a new manager and loads persisted state from the database.
func NewIPStateManager(database *db.DB) *IPStateManager {
	return &IPStateManager{
		states:   make(map[string]*IPState),
		database: database,
		quit:     make(chan struct{}),
	}
}

// Start loads persisted state and begins background goroutines.
func (m *IPStateManager) Start(ctx context.Context) error {
	if err := m.loadFromDB(ctx); err != nil {
		slog.Error("waf ip state: failed to load from DB", "error", err)
		// Not fatal — we can operate without persisted state
	}

	m.wg.Add(2)
	go m.persistLoop()
	go m.cleanupLoop()

	return nil
}

// Stop signals background goroutines to stop and does a final persist.
func (m *IPStateManager) Stop(ctx context.Context) {
	close(m.quit)
	m.wg.Wait()
	m.persistAll(ctx)
}

// IsBanned checks if an IP is currently banned. Returns ban status and reason.
func (m *IPStateManager) IsBanned(ip string) (bool, string) {
	m.mu.RLock()
	state, ok := m.states[ip]
	m.mu.RUnlock()

	if !ok {
		return false, ""
	}

	switch state.Status {
	case ActionBan:
		return true, state.BanReason
	case ActionTempBan:
		if time.Now().Before(state.BanUntil) {
			return true, state.BanReason
		}
		// Temp ban expired — clear it
		m.mu.Lock()
		state.Status = ActionAllow
		state.BanReason = ""
		state.Dirty = true
		m.mu.Unlock()
		return false, ""
	default:
		return false, ""
	}
}

// IsWhitelisted checks if an IP is whitelisted.
func (m *IPStateManager) IsWhitelisted(ip string) bool {
	m.mu.RLock()
	state, ok := m.states[ip]
	m.mu.RUnlock()
	return ok && state.Whitelisted
}

// GetOrCreate returns the state for an IP, creating a new one if needed.
func (m *IPStateManager) GetOrCreate(ip string) *IPState {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.states[ip]
	if !ok {
		state = &IPState{
			Status:   ActionAllow,
			LastSeen: time.Now(),
		}
		m.states[ip] = state
	}
	return state
}

// UpdateScore adds a hit and recalculates the IP's cumulative score.
// Returns the new cumulative score.
func (m *IPStateManager) UpdateScore(ip string, requestScore int, cfg *WafConfig) float64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.states[ip]
	if !ok {
		state = &IPState{
			Status: ActionAllow,
		}
		m.states[ip] = state
	}

	now := time.Now()
	ipScore := state.AddHit(requestScore, now, cfg.IPScoreWindowHours, cfg.IPScoreDecayPerHour)

	// Update status based on score
	action := DetermineAction(ipScore, cfg)
	if ActionSeverityOrder(action) > ActionSeverityOrder(state.Status) || state.Status == ActionAllow {
		state.Status = action
		if action == ActionTempBan {
			state.BanUntil = now.Add(time.Duration(cfg.TempBanDurationMinutes) * time.Minute)
			state.BanReason = "cumulative_score"
		} else if action == ActionBan {
			state.BanUntil = now.Add(24 * time.Hour) // ban for 24h, configurable
			state.BanReason = "cumulative_score"
		}
	}

	return ipScore
}

// ManualBan bans an IP manually (admin action).
func (m *IPStateManager) ManualBan(ip, reason string, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.states[ip]
	if !ok {
		state = &IPState{}
		m.states[ip] = state
	}

	state.Status = ActionBan
	state.BanReason = reason
	state.BanUntil = time.Now().Add(duration)
	state.LastSeen = time.Now()
	state.Dirty = true
}

// ManualUnban removes a ban from an IP.
func (m *IPStateManager) ManualUnban(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.states[ip]
	if !ok {
		return
	}

	state.Status = ActionAllow
	state.BanReason = ""
	state.BanUntil = time.Time{}
	state.CumulativeScore = 0
	state.Hits = nil
	state.Dirty = true
}

// SetWhitelisted adds an IP to the whitelist.
func (m *IPStateManager) SetWhitelisted(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.states[ip]
	if !ok {
		state = &IPState{}
		m.states[ip] = state
	}

	state.Whitelisted = true
	state.Status = ActionAllow
	state.BanReason = ""
	state.BanUntil = time.Time{}
	state.LastSeen = time.Now()
	state.Dirty = true
}

// RemoveWhitelist removes an IP from the whitelist.
func (m *IPStateManager) RemoveWhitelist(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.states[ip]
	if !ok {
		return
	}
	state.Whitelisted = false
	state.Dirty = true
}

// Stats returns counts by status.
func (m *IPStateManager) Stats() map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := map[string]int{
		"total":       len(m.states),
		"banned":      0,
		"temp_banned": 0,
		"whitelisted": 0,
		"active":      0,
	}

	for _, s := range m.states {
		switch {
		case s.Whitelisted:
			stats["whitelisted"]++
		case s.Status == ActionBan:
			stats["banned"]++
		case s.Status == ActionTempBan:
			stats["temp_banned"]++
		case s.CumulativeScore > 0:
			stats["active"]++
		}
	}
	return stats
}

// loadFromDB loads persisted IP states into memory.
func (m *IPStateManager) loadFromDB(ctx context.Context) error {
	states, err := m.database.ListWafIPStates(ctx)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, s := range states {
		ipState := &IPState{
			Status:          Action(s.Status),
			CumulativeScore: s.CumulativeScore,
			LastSeen:        s.LastSeen,
			BanReason:       s.BanReason,
			Whitelisted:     s.Status == "whitelisted",
		}
		if s.BanUntil != nil {
			ipState.BanUntil = *s.BanUntil
		}
		m.states[s.IP] = ipState
	}

	slog.Info("waf ip state loaded from DB", "count", len(states))
	return nil
}

// persistLoop writes dirty states to PostgreSQL every 60 seconds.
func (m *IPStateManager) persistLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			m.persistAll(ctx)
			cancel()
		case <-m.quit:
			return
		}
	}
}

// persistAll writes all dirty IP states to the database.
func (m *IPStateManager) persistAll(ctx context.Context) {
	m.mu.Lock()
	var dirtyIPs []struct {
		ip    string
		state IPState
	}
	for ip, state := range m.states {
		if state.Dirty {
			dirtyIPs = append(dirtyIPs, struct {
				ip    string
				state IPState
			}{ip: ip, state: *state})
			state.Dirty = false
		}
	}
	m.mu.Unlock()

	if len(dirtyIPs) == 0 {
		return
	}

	persisted := 0
	for _, d := range dirtyIPs {
		status := string(d.state.Status)
		if d.state.Whitelisted {
			status = "whitelisted"
		}

		var banUntil *time.Time
		if !d.state.BanUntil.IsZero() {
			t := d.state.BanUntil
			banUntil = &t
		}

		if err := m.database.UpsertWafIPState(ctx,
			d.ip, status, d.state.CumulativeScore, d.state.LastSeen,
			banUntil, d.state.BanReason,
		); err != nil {
			slog.Error("waf ip state persist failed", "ip", d.ip, "error", err)
			// Mark dirty again so we retry
			m.mu.Lock()
			if s, ok := m.states[d.ip]; ok {
				s.Dirty = true
			}
			m.mu.Unlock()
			continue
		}
		persisted++
	}

	if persisted > 0 {
		slog.Debug("waf ip state persisted", "count", persisted)
	}
}

// cleanupLoop removes stale IPs from memory every 5 minutes.
func (m *IPStateManager) cleanupLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.cleanup()
		case <-m.quit:
			return
		}
	}
}

func (m *IPStateManager) cleanup() {
	cutoff := time.Now().Add(-1 * time.Hour)

	m.mu.Lock()
	defer m.mu.Unlock()

	removed := 0
	for ip, state := range m.states {
		if state.CumulativeScore == 0 &&
			state.Status == ActionAllow &&
			!state.Whitelisted &&
			state.LastSeen.Before(cutoff) &&
			!state.Dirty {
			delete(m.states, ip)
			removed++
		}
	}

	if removed > 0 {
		slog.Debug("waf ip state cleanup", "removed", removed, "remaining", len(m.states))
	}
}
