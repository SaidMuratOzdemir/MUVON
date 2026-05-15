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

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "key generation failed"})
		return
	}
	apiKey := hex.EncodeToString(keyBytes)

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
	s.auditLog(r, "delete_agent", "agent", id, nil)
	w.WriteHeader(http.StatusNoContent)
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
