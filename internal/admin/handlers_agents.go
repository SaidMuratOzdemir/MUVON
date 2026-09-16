package admin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"muvon/internal/db"
)

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.db.ListAgents(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if agents == nil {
		agents = []db.Agent{}
	}
	writeJSON(w, http.StatusOK, agents)
}

// newAgentAPIKey returns 32 random bytes as hex, the shape every agent key has.
func newAgentAPIKey() (string, error) {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(keyBytes), nil
}

func (s *Server) handleCreateAgent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}

	apiKey, err := newAgentAPIKey()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "key generation failed"})
		return
	}

	agent, err := s.db.CreateAgent(r.Context(), req.Name, apiKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	s.auditLog(r, "create_agent", "agent", agent.ID, map[string]string{"name": req.Name})
	// Plaintext key is exposed exactly once — in this response. The
	// db.Agent struct intentionally hides APIKey from JSON, so we wrap
	// it together with the row to make the contract explicit.
	writeJSON(w, http.StatusCreated, map[string]any{
		"agent":   agent,
		"api_key": apiKey,
	})
}

// handleRevokeAgent cuts an agent's key on central, so it takes effect whether
// or not the agent is reachable. Both agent auth paths refuse the key from the
// next request, open watch streams and long polls end here, and commands the
// agent had not finished expire. The edge keeps serving its last config;
// coming back takes a new key from handleRotateAgentKey.
func (s *Server) handleRevokeAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	agent, err := s.db.RevokeAgent(r.Context(), id, adminUserID(r))
	if err != nil {
		if err == pgx.ErrNoRows {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.disconnectAgent(id)
	s.auditLog(r, "revoke_agent", "agent", id, map[string]string{"name": agent.Name})
	writeJSON(w, http.StatusOK, agent)
}

// handleRotateAgentKey replaces an agent's key, active or revoked, and returns
// the new one exactly once. The old key stops working at once; the agent row
// and its host and component bindings stay.
func (s *Server) handleRotateAgentKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	apiKey, err := newAgentAPIKey()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "key generation failed"})
		return
	}
	agent, err := s.db.RotateAgentKey(r.Context(), id, apiKey)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.disconnectAgent(id)
	s.auditLog(r, "rotate_agent_key", "agent", id, map[string]string{"name": agent.Name})
	writeJSON(w, http.StatusOK, map[string]any{
		"agent":   agent,
		"api_key": apiKey,
	})
}

func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.db.DeleteAgent(r.Context(), id); err != nil {
		if err == pgx.ErrNoRows {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.disconnectAgent(id)
	s.auditLog(r, "delete_agent", "agent", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

// disconnectAgent ends the agent's open requests once its key no longer
// works. Without the agent API there is nothing open to end.
func (s *Server) disconnectAgent(id string) {
	if s.agentSvc != nil {
		s.agentSvc.Disconnect(id)
	}
}

// handleUpdateAgentMounts replaces the operator-managed extra_mounts list
// for an agent. Paths are not validated against the agent host (we can't
// stat them from central); the operator is trusted to enter real paths.
// Empty / whitespace entries are dropped. Applying the new list to the
// live container still requires the operator to fire agent.self_upgrade
// from the UI — this endpoint only persists the desired state.
func (s *Server) handleUpdateAgentMounts(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		ExtraMounts []string `json:"extra_mounts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	cleaned := make([]string, 0, len(req.ExtraMounts))
	for _, p := range req.ExtraMounts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		cleaned = append(cleaned, p)
	}
	if err := s.db.UpdateAgentExtraMounts(r.Context(), id, cleaned); err != nil {
		if err == pgx.ErrNoRows {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.auditLog(r, "update_agent_mounts", "agent", id, map[string]any{"extra_mounts": cleaned})
	if err := s.triggerReload(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "saved but config reload failed: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"extra_mounts": cleaned})
}

// handleUpdateAgentDeployerAddr sets the host:port the central admin
// dials to stream live container logs for this agent's host. Trimmed;
// empty string disables the routing (live tail will surface a clear
// "configure deployer_addr" message).
func (s *Server) handleUpdateAgentDeployerAddr(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		DeployerAddr string `json:"deployer_addr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	addr := strings.TrimSpace(req.DeployerAddr)
	if err := s.db.UpdateAgentDeployerAddr(r.Context(), id, addr); err != nil {
		if err == pgx.ErrNoRows {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.auditLog(r, "update_agent_deployer_addr", "agent", id, map[string]any{"deployer_addr": addr})
	writeJSON(w, http.StatusOK, map[string]any{"deployer_addr": addr})
}
