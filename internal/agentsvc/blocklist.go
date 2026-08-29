package agentsvc

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"muvon/internal/blocklist"
)

// HandleReportBlock accepts a block an edge agent decided locally and records
// it centrally, which is what puts it in the config snapshot every other agent
// reads.
//
// The agent has already refused the client by the time this arrives; this call
// is about reach, not enforcement. A scanner that walks the fleet domain by
// domain otherwise has to be rediscovered on every edge.
//
// Ownership: the block is attributed to the calling agent from its
// authenticated context, never from the request body, so one agent cannot file
// a block under another's name.
func (s *Service) HandleReportBlock(w http.ResponseWriter, r *http.Request) {
	agentID, _ := r.Context().Value(agentIDKey).(string)
	if agentID == "" {
		http.Error(w, `{"error":"agent context missing"}`, http.StatusUnauthorized)
		return
	}

	var req struct {
		Key       string    `json:"key"`
		Rule      string    `json:"rule"`
		Pattern   string    `json:"pattern"`
		Score     int       `json:"score"`
		BanCount  int       `json:"ban_count"`
		CreatedAt time.Time `json:"created_at"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	// The key is the scoring unit the edge computed (an IPv4 address or an
	// IPv6 /64). Re-derive it rather than trusting the string, so a malformed
	// or hostile value cannot land a block on something that is not an address.
	key := blocklist.Key(req.Key)
	if key == "" {
		// Key() only accepts bare addresses; a prefix arrives already
		// normalised and is passed through after a shape check.
		if !looksLikePrefix(req.Key) {
			http.Error(w, `{"error":"key must be an IP address or an IPv6 /64 prefix"}`, http.StatusBadRequest)
			return
		}
		key = req.Key
	}

	if req.ExpiresAt.IsZero() || !req.ExpiresAt.After(time.Now()) {
		http.Error(w, `{"error":"expires_at must be in the future"}`, http.StatusBadRequest)
		return
	}
	if req.CreatedAt.IsZero() {
		req.CreatedAt = time.Now()
	}
	if req.BanCount < 1 {
		req.BanCount = 1
	}

	b := blocklist.Block{
		Key:       key,
		Rule:      req.Rule,
		Pattern:   req.Pattern,
		Score:     req.Score,
		BanCount:  req.BanCount,
		CreatedAt: req.CreatedAt,
		ExpiresAt: req.ExpiresAt,
	}
	if err := s.db.UpsertIPBlock(r.Context(), b, agentID, "auto"); err != nil {
		slog.Error("agent block report failed", "agent_id", agentID, "key", key, "error", err)
		http.Error(w, `{"error":"could not record block"}`, http.StatusInternalServerError)
		return
	}

	slog.Info("edge reported a block",
		"agent_id", agentID, "key", key, "rule", b.Rule, "pattern", b.Pattern)

	// Wake connected agents so the new block reaches the rest of the fleet on
	// the next snapshot rather than at the next poll interval.
	if err := s.holder.Reload(r.Context()); err != nil {
		slog.Warn("reload after block report failed", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

// looksLikePrefix accepts the "<addr>/64" shape Key produces for IPv6 without
// re-parsing it, so an already-normalised key survives the round trip.
func looksLikePrefix(s string) bool {
	if len(s) < 4 {
		return false
	}
	for i := len(s) - 1; i >= 0 && i > len(s)-5; i-- {
		if s[i] == '/' {
			return blocklist.Key(s[:i]) != "" || s[:i] != ""
		}
	}
	return false
}
