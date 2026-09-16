package admin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"muvon/internal/agentctrl"
	"muvon/internal/agentsvc"
	"muvon/internal/testpg"
)

type agentAPI struct {
	t       *testing.T
	dbs     testpg.DBs
	admin   *http.ServeMux
	central *httptest.Server
}

func newAgentAPI(t *testing.T) *agentAPI {
	t.Helper()
	dbs := testpg.Open(t)
	svc := agentsvc.NewService(dbs.Muvon, nil, agentsvc.NewBroadcaster())
	svc.SetCommandSigningKey([]byte("test-signing-key"))
	srv := &Server{db: dbs.Muvon, agentSvc: svc}

	admin := http.NewServeMux()
	admin.HandleFunc("POST /api/agents", srv.handleCreateAgent)
	admin.HandleFunc("POST /api/agents/{id}/revoke", srv.handleRevokeAgent)
	admin.HandleFunc("POST /api/agents/{id}/rotate-key", srv.handleRotateAgentKey)
	admin.HandleFunc("DELETE /api/agents/{id}", srv.handleDeleteAgent)
	admin.HandleFunc("POST /api/agents/{id}/commands", srv.handleEnqueueAgentCommand)

	agentMux := http.NewServeMux()
	agentMux.HandleFunc("GET /api/v1/agent/watch", svc.HandleWatch)
	agentMux.HandleFunc("GET /api/v1/agent/commands", svc.HandlePollCommand)
	central := httptest.NewServer(svc.AuthMiddleware(agentMux))
	t.Cleanup(central.Close)
	return &agentAPI{t: t, dbs: dbs, admin: admin, central: central}
}

func (a *agentAPI) call(method, path string, body any) (int, map[string]any) {
	a.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			a.t.Fatal(err)
		}
	}
	rec := httptest.NewRecorder()
	a.admin.ServeHTTP(rec, httptest.NewRequest(method, path, &buf))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// agentGet sends an agent API request with key and returns the status and body.
func (a *agentAPI) agentGet(path, key string) (int, string) {
	a.t.Helper()
	req, err := http.NewRequest(http.MethodGet, a.central.URL+path, nil)
	if err != nil {
		a.t.Fatal(err)
	}
	req.Header.Set("X-Api-Key", key)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestRevokingAnAgentCutsItsKeyOnCentral(t *testing.T) {
	a := newAgentAPI(t)
	ctx := context.Background()

	code, created := a.call("POST", "/api/agents", map[string]string{"name": "edge-1"})
	if code != http.StatusCreated {
		t.Fatalf("create agent = %d %v", code, created)
	}
	agentID := created["agent"].(map[string]any)["id"].(string)
	key := created["api_key"].(string)

	if code, body := a.call("POST", "/api/agents/"+agentID+"/commands", map[string]any{"kind": "agent.cache_flush"}); code != http.StatusAccepted {
		t.Fatalf("enqueue before revoke = %d %v", code, body)
	}

	// A watch stream opened with the key must end when the key is revoked.
	req, _ := http.NewRequest(http.MethodGet, a.central.URL+"/api/v1/agent/watch", nil)
	req.Header.Set("X-Api-Key", key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("watch before revoke = %d", resp.StatusCode)
	}
	reader := bufio.NewReader(resp.Body)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("watch first line: %v", err)
	}
	streamEnded := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, reader)
		close(streamEnded)
	}()

	code, revoked := a.call("POST", "/api/agents/"+agentID+"/revoke", nil)
	if code != http.StatusOK || revoked["is_active"] != false || revoked["revoked_at"] == nil {
		t.Fatalf("revoke = %d %v", code, revoked)
	}
	select {
	case <-streamEnded:
	case <-time.After(5 * time.Second):
		t.Fatal("watch stream kept running after the key was revoked")
	}

	status, body := a.agentGet("/api/v1/agent/commands?wait=1", key)
	if !agentctrl.IsRevoked(status, []byte(body)) {
		t.Fatalf("poll with revoked key = %d %q, want 401 %q", status, body, agentctrl.RevokedMessage)
	}

	var pending int
	if err := a.dbs.Muvon.Pool.QueryRow(ctx,
		`SELECT count(*) FROM muvon.agent_commands WHERE agent_id = $1 AND state IN ('pending','dispatched')`,
		agentID).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("unfinished commands after revoke = %d (%v), want 0", pending, err)
	}
	if code, body := a.call("POST", "/api/agents/"+agentID+"/commands", map[string]any{"kind": "agent.cache_flush"}); code != http.StatusConflict {
		t.Fatalf("enqueue after revoke = %d %v, want 409", code, body)
	}

	// A new key brings the agent back; the revoked key stays dead.
	code, rotated := a.call("POST", "/api/agents/"+agentID+"/rotate-key", nil)
	if code != http.StatusOK {
		t.Fatalf("rotate = %d %v", code, rotated)
	}
	newKey := rotated["api_key"].(string)
	if rotated["agent"].(map[string]any)["is_active"] != true || rotated["agent"].(map[string]any)["revoked_at"] != nil {
		t.Fatalf("rotated agent = %v, want active and not revoked", rotated["agent"])
	}
	if status, body := a.agentGet("/api/v1/agent/commands?wait=1", key); status != http.StatusUnauthorized || strings.Contains(body, agentctrl.RevokedMessage) {
		t.Fatalf("old key after rotation = %d %q, want 401 invalid key", status, body)
	}
	if status, body := a.agentGet("/api/v1/agent/commands?wait=1", newKey); status != http.StatusNoContent {
		t.Fatalf("new key = %d %q, want 204", status, body)
	}
}

// deploy_components.agent_id is SET NULL when its agent goes; a scheduled job
// bound to the same agent must not stop the delete.
func TestDeletingAnAgentWithAScheduledJob(t *testing.T) {
	a := newAgentAPI(t)
	ctx := context.Background()

	code, created := a.call("POST", "/api/agents", map[string]string{"name": "edge-2"})
	if code != http.StatusCreated {
		t.Fatalf("create agent = %d %v", code, created)
	}
	agentID := created["agent"].(map[string]any)["id"].(string)
	seed := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO muvon.deploy_projects (slug, name) VALUES ('shop', 'Shop')`, nil},
		{`INSERT INTO muvon.deploy_components (project_id, slug, name, image_repo, internal_port, agent_id)
		  SELECT id, 'worker', 'Worker', 'registry.example.com/shop', 8000, $1 FROM muvon.deploy_projects WHERE slug = 'shop'`, []any{agentID}},
		{`INSERT INTO muvon.scheduled_jobs (project_id, component_id, agent_id, name, slug, schedule)
		  SELECT c.project_id, c.id, $1, 'Report', 'report', '0 * * * *' FROM muvon.deploy_components c WHERE c.slug = 'worker'`, []any{agentID}},
	}
	for _, s := range seed {
		if _, err := a.dbs.Muvon.Pool.Exec(ctx, s.sql, s.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	if code, body := a.call("DELETE", "/api/agents/"+agentID, nil); code != http.StatusNoContent {
		t.Fatalf("delete agent with a scheduled job = %d %v, want 204", code, body)
	}
	var jobAgent *string
	if err := a.dbs.Muvon.Pool.QueryRow(ctx, `SELECT agent_id FROM muvon.scheduled_jobs WHERE slug = 'report'`).Scan(&jobAgent); err != nil || jobAgent != nil {
		t.Fatalf("scheduled job agent_id after delete = %v (%v), want NULL", jobAgent, err)
	}
}
