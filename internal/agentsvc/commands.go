package agentsvc

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// HTTP endpoints for the central → agent command channel.
//
//   GET  /api/v1/agent/commands?wait=25s        long-poll, X-Api-Key auth
//   POST /api/v1/agent/commands/{id}/result     terminal report, X-Api-Key auth
//
// The corresponding admin-side enqueue handler lives in internal/admin
// (handlers_agent_commands.go) so admin auth (JWT) stays separate.

// HandlePollCommand is the agent's long-poll endpoint. Returns 200 with
// the command body, 204 when no command was ready before the timeout,
// or 5xx on DB/server error. The "wait" query param caps how long the
// server holds the connection — default 25s (just under the agent's
// 30s HTTP client timeout), max 50s.
func (s *Service) HandlePollCommand(w http.ResponseWriter, r *http.Request) {
	agentID, _ := r.Context().Value(agentIDKey).(string)
	if agentID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing agent id"})
		return
	}

	wait := 25 * time.Second
	if v := r.URL.Query().Get("wait"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			d := time.Duration(secs) * time.Second
			if d > 50*time.Second {
				d = 50 * time.Second
			}
			wait = d
		}
	}

	// Fast path: command already pending? Return immediately.
	if cmd, ok, err := s.db.ClaimNextAgentCommand(r.Context(), agentID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	} else if ok {
		writeJSON(w, http.StatusOK, cmd)
		return
	}

	// Slow path: subscribe to wake bus, then race wake / timeout / ctx.
	wake, cancel := s.commandBus.Subscribe(agentID)
	defer cancel()

	select {
	case <-wake:
		// Wake doesn't guarantee a row (e.g. command expired between
		// notify and claim). Try once more, return 204 if missed.
		if cmd, ok, err := s.db.ClaimNextAgentCommand(r.Context(), agentID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		} else if ok {
			writeJSON(w, http.StatusOK, cmd)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case <-time.After(wait):
		w.WriteHeader(http.StatusNoContent)
	case <-r.Context().Done():
		// Client closed the connection — nothing to write.
		return
	}
}

// HandleCommandResult records the agent's terminal report for a
// command. Idempotent at the DB level (FinishAgentCommand rejects
// already-terminal rows), so a duplicate POST is safely 409'd.
func (s *Service) HandleCommandResult(w http.ResponseWriter, r *http.Request) {
	agentID, _ := r.Context().Value(agentIDKey).(string)
	if agentID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing agent id"})
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing command id"})
		return
	}
	var body struct {
		State  string          `json:"state"`
		Output string          `json:"output"`
		Error  string          `json:"error"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if body.State != "succeeded" && body.State != "failed" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "state must be succeeded or failed"})
		return
	}
	resultJSON, _ := json.Marshal(map[string]any{
		"output": body.Output,
		"error":  body.Error,
		"data":   body.Data,
	})
	if err := s.db.FinishAgentCommand(r.Context(), agentID, id, body.State, resultJSON); err != nil {
		// Already terminal counts as "OK we got it" — operator sees a
		// 409 in logs but it's not a problem.
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
