package config

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// AgentSource loads configuration from the central server via HTTP.
// Used by agent binaries running on client servers.
type AgentSource struct {
	centralURL string
	apiKey     string
	// publicIP is the agent's externally-reachable IP (operator-supplied
	// or auto-detected at install). Sent on every config pull / SSE
	// reconnect as X-Agent-Public-IP so central can store the right DNS
	// target — last_remote_addr alone is unreliable in private-network
	// topologies.
	publicIP   string
	// hostID is the string the agent uses as container_logs.host_id when
	// shipping to dialog. Sent as X-Muvon-Host-Id so central can persist
	// the mapping (agents.host_id) and dial the right agent for live tail.
	hostID     string
	httpClient *http.Client

	// lastVersion tracks the snapshot we last applied, so subsequent
	// requests can echo it back via X-Config-Version. Central uses that
	// header to record which config version each agent is actually
	// running, separate from "agent is alive on the SSE channel".
	lastVersionMu sync.RWMutex
	lastVersion   string

	// extraMounts is the operator-managed bind-mount list from the most
	// recent config pull. Stored here (not in the Holder/Config) because
	// it's a deployment-time concern that only the self_upgrade command
	// reads, never the hot proxy path.
	extraMountsMu sync.RWMutex
	extraMounts   []string

	// cachePath is an optional disk path where the most recently
	// successful AgentPayload is stored. Init reads it when central is
	// unreachable so the proxy can start serving stale-but-working
	// config instead of crash-looping. Empty = caching disabled.
	cachePath string
}

func NewAgentSource(centralURL, apiKey string) *AgentSource {
	return &AgentSource{
		centralURL: strings.TrimRight(centralURL, "/"),
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// SetPublicIP configures the agent's externally-reachable IP. Empty
// string is allowed and disables the header (central then falls back
// to last_remote_addr, which is fine for non-NAT setups).
func (s *AgentSource) SetPublicIP(ip string) {
	s.publicIP = strings.TrimSpace(ip)
}

// SetHostID configures the agent's logship host_id. Sent on every
// config pull and SSE reconnect so central can map this agent's
// container dimension rows back to the agent record.
func (s *AgentSource) SetHostID(id string) {
	s.hostID = strings.TrimSpace(id)
}

// LastExtraMounts returns the operator-managed bind paths from the most
// recent config pull. Callers (agent.self_upgrade handler) consult this
// to thread the list into the helper container that rewrites compose.
// Empty slice = no extra mounts configured.
func (s *AgentSource) LastExtraMounts() []string {
	s.extraMountsMu.RLock()
	defer s.extraMountsMu.RUnlock()
	out := make([]string, len(s.extraMounts))
	copy(out, s.extraMounts)
	return out
}

func (s *AgentSource) setExtraMounts(m []string) {
	s.extraMountsMu.Lock()
	s.extraMounts = m
	s.extraMountsMu.Unlock()
}

// EnableLocalCache routes successful Loads through `path` (atomic
// write) and tries to recover stale config from the same path when
// central is unreachable. Pass "" to disable. Returning an error is
// non-fatal — the caller logs and proceeds without caching.
func (s *AgentSource) EnableLocalCache(path string) error {
	s.cachePath = strings.TrimSpace(path)
	if s.cachePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.cachePath), 0o755); err != nil {
		return fmt.Errorf("agent source: create cache dir: %w", err)
	}
	return nil
}

// LoadCached returns the most recent payload persisted by EnableLocalCache.
// Used as a fallback when the central server is unreachable on startup.
// Returns an error when no cache path is set or the file is missing/bad.
func (s *AgentSource) LoadCached() (*Config, error) {
	if s.cachePath == "" {
		return nil, fmt.Errorf("agent source: no local cache configured")
	}
	raw, err := os.ReadFile(s.cachePath)
	if err != nil {
		return nil, fmt.Errorf("agent source: read cache: %w", err)
	}
	var payload AgentPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("agent source: parse cache: %w", err)
	}
	if payload.Version != "" {
		s.setLastVersion(payload.Version)
	}
	s.setExtraMounts(payload.ExtraMounts)
	cfg := payload.ToConfig()
	slog.Warn("config loaded from local cache (central unreachable)",
		"hosts", len(cfg.Hosts), "cached_version", payload.Version, "path", s.cachePath)
	return cfg, nil
}

// writeCache persists the most recent successful payload atomically so a
// crash mid-write never leaves a half-truncated file.
func (s *AgentSource) writeCache(raw []byte) {
	if s.cachePath == "" {
		return
	}
	tmp := s.cachePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		slog.Warn("agent source: write config cache failed", "error", err)
		return
	}
	if err := os.Rename(tmp, s.cachePath); err != nil {
		slog.Warn("agent source: rename config cache failed", "error", err)
		_ = os.Remove(tmp)
	}
}

// LastVersion returns the most recent config version this agent has applied.
func (s *AgentSource) LastVersion() string {
	s.lastVersionMu.RLock()
	defer s.lastVersionMu.RUnlock()
	return s.lastVersion
}

func (s *AgentSource) setLastVersion(v string) {
	s.lastVersionMu.Lock()
	s.lastVersion = v
	s.lastVersionMu.Unlock()
}

// Load fetches the current config from the central server.
func (s *AgentSource) Load(ctx context.Context) (*Config, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", s.centralURL+"/api/v1/agent/config", nil)
	if err != nil {
		return nil, fmt.Errorf("agent source: %w", err)
	}
	req.Header.Set("X-Api-Key", s.apiKey)
	if s.publicIP != "" {
		req.Header.Set("X-Agent-Public-IP", s.publicIP)
	}
	if s.hostID != "" {
		req.Header.Set("X-Muvon-Host-Id", s.hostID)
	}
	if v := s.LastVersion(); v != "" {
		// Lets central distinguish "agent missed a push" from "agent is
		// reapplying the same snapshot" without us having to emit a
		// separate heartbeat endpoint.
		req.Header.Set("X-Config-Version", v)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agent source: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("agent source: central returned %d: %s", resp.StatusCode, body)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("agent source: read body: %w", err)
	}
	var payload AgentPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("agent source: decode failed: %w", err)
	}

	if payload.Version != "" {
		s.setLastVersion(payload.Version)
	}
	// Operator-managed bind paths — stash them so the self_upgrade
	// handler can hand them off to the helper container later.
	s.setExtraMounts(payload.ExtraMounts)
	// Persist the verbatim payload (not the lossy *Config view) so a
	// cold-start can rebuild every field — including ones ToConfig
	// flattens for runtime use.
	s.writeCache(raw)

	cfg := payload.ToConfig()
	slog.Info("config loaded from central", "hosts", len(cfg.Hosts), "version", payload.Version)
	return cfg, nil
}

// Watch opens an SSE stream to the central server and calls onUpdate whenever
// the central pushes a config_updated event. Blocks until ctx is cancelled.
// Automatically reconnects on disconnect.
func (s *AgentSource) Watch(ctx context.Context, onUpdate func()) {
	for {
		if err := s.watchOnce(ctx, onUpdate); err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("config watch disconnected, reconnecting in 5s", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (s *AgentSource) watchOnce(ctx context.Context, onUpdate func()) error {
	req, err := http.NewRequestWithContext(ctx, "GET", s.centralURL+"/api/v1/agent/watch", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", s.apiKey)
	req.Header.Set("Accept", "text/event-stream")

	// No timeout for SSE — connection stays open indefinitely.
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if scanner.Text() == "event: config_updated" {
			onUpdate()
		}
	}
	return scanner.Err()
}
