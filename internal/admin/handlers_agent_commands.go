package admin

import (
	"encoding/json"
	"net/http"
	"time"

	"muvon/internal/agentctrl"
	"muvon/internal/db"
)

// Admin-side handlers for the central → agent command channel.
//
//   POST /api/agents/{id}/commands               enqueue (JWT auth)
//   GET  /api/agents/{id}/commands               recent history (JWT auth)
//
// The signed command body is built here, written to the DB, then the
// in-memory command bus is woken so the agent's long-poll returns
// immediately. Signature verification happens on the agent side using
// the same MUVON_ENCRYPTION_KEY → HKDF derivation.

func (s *Server) handleEnqueueAgentCommand(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if agentID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing agent id"})
		return
	}
	if s.agentSvc == nil || !s.agentSvc.HasCommandSigning() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "command channel disabled (MUVON_ENCRYPTION_KEY not set)",
		})
		return
	}
	// Verify agent exists + active before enqueueing — saves a row in
	// the table for typo'd agent IDs and gives the operator a clear
	// error.
	agent, err := s.db.GetAgent(r.Context(), agentID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
		return
	}
	if !agent.IsActive {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "agent is disabled"})
		return
	}

	var req struct {
		Kind       string          `json:"kind"`
		Payload    json.RawMessage `json:"payload"`
		TTLSeconds int             `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if !knownCommandKind(req.Kind) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown command kind: " + req.Kind})
		return
	}
	if req.TTLSeconds <= 0 {
		req.TTLSeconds = 300 // 5 min default
	}
	if req.TTLSeconds > 3600 {
		req.TTLSeconds = 3600 // 1h cap
	}
	expiresAt := time.Now().Add(time.Duration(req.TTLSeconds) * time.Second)

	nonce, err := agentctrl.NewNonce()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "nonce generation failed"})
		return
	}

	// Pre-INSERT we don't have the ID yet (DB picks UUIDv7) — so we
	// insert first, then sign using the returned ID, then UPDATE the
	// signature column. This keeps the canonical signing input keyed
	// by the actual row ID rather than a client-side guess.
	payload := req.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	cmd, err := s.db.EnqueueAgentCommand(r.Context(), db.EnqueueAgentCommandInput{
		AgentID:   agentID,
		Kind:      req.Kind,
		Payload:   payload,
		ExpiresAt: expiresAt,
		Nonce:     nonce,
		Signature: []byte{}, // placeholder, updated below
		IssuedBy:  adminUserID(r),
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	sig, err := agentctrl.Sign(agentctrl.Command{
		ID:        cmd.ID,
		Kind:      agentctrl.CommandKind(cmd.Kind),
		Payload:   cmd.Payload,
		ExpiresAt: cmd.ExpiresAt,
		Nonce:     nonce,
	}, s.agentSvc.SigningKey())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "signing failed: " + err.Error()})
		return
	}
	if err := s.db.UpdateAgentCommandSignature(r.Context(), cmd.ID, sig); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Wake the agent's long-poll. If the agent isn't connected the wake
	// is a no-op — the agent will pick the command up on its next poll.
	s.agentSvc.CommandBus().Wake(agentID)

	s.auditLog(r, "agent.command.enqueue", "agent", agentID, map[string]any{
		"command_id": cmd.ID,
		"kind":       cmd.Kind,
	})

	// Strip protocol-internal fields from the admin response.
	cmd.Nonce = nil
	cmd.Signature = nil
	writeJSON(w, http.StatusAccepted, cmd)
}

func (s *Server) handleListAgentCommands(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if agentID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing agent id"})
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := jsonNumber(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	rows, err := s.db.ListAgentCommands(r.Context(), agentID, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if rows == nil {
		rows = []db.AgentCommand{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// knownCommandKind validates the kind against the registry. Centralised
// here so a typo'd kind never makes it into the DB.
func knownCommandKind(s string) bool {
	for _, k := range agentctrl.AllKinds {
		if string(k) == s {
			return true
		}
	}
	return false
}

// adminUserID extracts the JWT subject if present. Falls back to
// "system" so script-driven enqueues still record provenance.
func adminUserID(r *http.Request) string {
	if v, ok := r.Context().Value(usernameKey).(string); ok && v != "" {
		return v
	}
	if v, ok := r.Context().Value(userIDKey).(int); ok && v > 0 {
		return "user:" + jsonStringInt(v)
	}
	return "system"
}

func jsonStringInt(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = '0' + byte(n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// jsonNumber parses a small positive int from a query string.
func jsonNumber(s string) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errInvalidNumber
		}
		n = n*10 + int(c-'0')
		if n > 1_000_000 {
			return 0, errInvalidNumber
		}
	}
	return n, nil
}

var errInvalidNumber = stringError("invalid number")

type stringError string

func (e stringError) Error() string { return string(e) }
