package deployer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"muvon/internal/db"
)

// APIState is the State implementation used by the embedded edge
// deployer in cmd/agent. Every method round-trips to central's
// /api/v1/agent/deployer/* endpoints over HTTP with X-Api-Key auth, so
// the same Service.Run() loop works for both topologies without knowing
// which side it's on.
//
// All requests run with a default timeout — long-running waits (image
// pull, container start, health check) happen locally; only the small
// state writes go over the wire.
type APIState struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewAPIState returns a State that talks to central. baseURL must point
// at the admin server (e.g. https://muvon.example.com), apiKey must be a
// valid agents.api_key row. The HTTP client uses a 15s timeout per call
// — long enough to ride out brief central restarts, short enough that a
// hung central never wedges the agent loop.
func NewAPIState(baseURL, apiKey string) *APIState {
	return &APIState{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		client:  &http.Client{Timeout: 15 * time.Second},
	}
}

func (s *APIState) do(ctx context.Context, method, path string, body any, out any) (int, error) {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("encode body: %w", err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.baseURL+path, reader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-Api-Key", s.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}
	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, fmt.Errorf("api state %s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

func (s *APIState) Claim(ctx context.Context) (db.Deployment, bool, error) {
	var dep db.Deployment
	status, err := s.do(ctx, http.MethodPost, "/api/v1/agent/deployer/claim", nil, &dep)
	if err != nil {
		// 204 lands here only when out!=nil + empty body; pass through.
		if status == http.StatusNoContent {
			return db.Deployment{}, false, nil
		}
		return db.Deployment{}, false, err
	}
	if status == http.StatusNoContent {
		return db.Deployment{}, false, nil
	}
	return dep, true, nil
}

func (s *APIState) LoadPlan(ctx context.Context, deploymentID string) (db.DeploymentPlan, error) {
	var plan db.DeploymentPlan
	_, err := s.do(ctx, http.MethodGet, "/api/v1/agent/deployer/plan/"+url.PathEscape(deploymentID), nil, &plan)
	return plan, err
}

func (s *APIState) AddEvent(ctx context.Context, deploymentID, eventType, message string, detail any) error {
	var detailRaw json.RawMessage
	if detail != nil {
		b, err := json.Marshal(detail)
		if err != nil {
			return fmt.Errorf("encode event detail: %w", err)
		}
		detailRaw = b
	}
	body := map[string]any{
		"deployment_id": deploymentID,
		"event_type":    eventType,
		"message":       message,
		"detail":        detailRaw,
	}
	_, err := s.do(ctx, http.MethodPost, "/api/v1/agent/deployer/event", body, nil)
	return err
}

func (s *APIState) Fail(ctx context.Context, deploymentID, message string) error {
	body := map[string]string{"deployment_id": deploymentID, "message": message}
	_, err := s.do(ctx, http.MethodPost, "/api/v1/agent/deployer/fail", body, nil)
	return err
}

func (s *APIState) CreateInstance(ctx context.Context, componentID int, releaseUUID, containerID, containerName, backendURL string) (db.DeployInstance, error) {
	body := map[string]any{
		"component_id":   componentID,
		"release_uuid":   releaseUUID,
		"container_id":   containerID,
		"container_name": containerName,
		"backend_url":    backendURL,
	}
	var inst db.DeployInstance
	_, err := s.do(ctx, http.MethodPost, "/api/v1/agent/deployer/instance", body, &inst)
	return inst, err
}

func (s *APIState) MarkInstanceUnhealthy(ctx context.Context, instanceID, message string) error {
	body := map[string]string{"instance_id": instanceID, "message": message}
	_, err := s.do(ctx, http.MethodPost, "/api/v1/agent/deployer/instance/unhealthy", body, nil)
	return err
}

func (s *APIState) Promote(ctx context.Context, deploymentID string, candidateIDs []string) error {
	body := map[string]any{"deployment_id": deploymentID, "candidate_ids": candidateIDs}
	_, err := s.do(ctx, http.MethodPost, "/api/v1/agent/deployer/promote", body, nil)
	return err
}

func (s *APIState) ResetStaleRunning(ctx context.Context, olderThan time.Duration) (int, error) {
	body := map[string]int{"older_than_seconds": int(olderThan / time.Second)}
	var resp struct{ Reset int `json:"reset"` }
	_, err := s.do(ctx, http.MethodPost, "/api/v1/agent/deployer/reset-stale", body, &resp)
	return resp.Reset, err
}

func (s *APIState) CleanupStaleWarming(ctx context.Context) (int, error) {
	var resp struct{ Cleaned int `json:"cleaned"` }
	_, err := s.do(ctx, http.MethodPost, "/api/v1/agent/deployer/cleanup-warming", nil, &resp)
	return resp.Cleaned, err
}

func (s *APIState) ListDrainable(ctx context.Context) ([]db.DeployInstance, error) {
	var out []db.DeployInstance
	_, err := s.do(ctx, http.MethodGet, "/api/v1/agent/deployer/drainable", nil, &out)
	return out, err
}

func (s *APIState) MarkInstanceStopped(ctx context.Context, instanceID string) error {
	body := map[string]string{"instance_id": instanceID}
	_, err := s.do(ctx, http.MethodPost, "/api/v1/agent/deployer/instance/stopped", body, nil)
	return err
}

func (s *APIState) ListLiveManagedContainerIDs(ctx context.Context) (map[string]struct{}, error) {
	var resp struct {
		ContainerIDs []string `json:"container_ids"`
	}
	_, err := s.do(ctx, http.MethodGet, "/api/v1/agent/deployer/live-containers", nil, &resp)
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{}, len(resp.ContainerIDs))
	for _, id := range resp.ContainerIDs {
		out[id] = struct{}{}
	}
	return out, nil
}

func (s *APIState) ListPrunableImageRefs(ctx context.Context, componentID, keepN int) ([]string, error) {
	var resp struct {
		ImageRefs []string `json:"image_refs"`
	}
	body := map[string]int{"component_id": componentID, "keep_n": keepN}
	_, err := s.do(ctx, http.MethodPost, "/api/v1/agent/deployer/prunable-images", body, &resp)
	return resp.ImageRefs, err
}
