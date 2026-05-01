package config

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AgentSource loads configuration from the central server via HTTP.
// Used by agent binaries running on client servers.
type AgentSource struct {
	centralURL string
	apiKey     string
	httpClient *http.Client

	// lastVersion tracks the snapshot we last applied, so subsequent
	// requests can echo it back via X-Config-Version. Central uses that
	// header to record which config version each agent is actually
	// running, separate from "agent is alive on the SSE channel".
	lastVersionMu sync.RWMutex
	lastVersion   string
}

func NewAgentSource(centralURL, apiKey string) *AgentSource {
	return &AgentSource{
		centralURL: strings.TrimRight(centralURL, "/"),
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 15 * time.Second},
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

	var payload AgentPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("agent source: decode failed: %w", err)
	}

	if payload.Version != "" {
		s.setLastVersion(payload.Version)
	}

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
