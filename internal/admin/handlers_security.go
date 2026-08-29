package admin

import (
	"encoding/json"
	"net/http"
	"strings"

	"muvon/internal/blocklist"
)

// handleListBlockPatterns returns the whole pattern table, disabled rows
// included: the operator needs to see what they switched off, not just what is
// live.
func (s *Server) handleListBlockPatterns(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.ListBlocklistPatterns(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if rows == nil {
		rows = []blocklist.Pattern{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// handleUpsertBlockPattern creates an operator pattern or edits an existing one.
//
// The pattern is compiled before it is stored. A regex that does not compile is
// refused here rather than being written and silently skipped at load time,
// because a pattern the operator believes is protecting them and is not is
// worse than no pattern at all.
func (s *Server) handleUpsertBlockPattern(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind    string `json:"kind"`
		Pattern string `json:"pattern"`
		Score   int    `json:"score"`
		Rule    string `json:"rule"`
		Enabled *bool  `json:"enabled"`
		Note    string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	req.Kind = strings.TrimSpace(strings.ToLower(req.Kind))
	req.Pattern = strings.TrimSpace(strings.ToLower(req.Pattern))
	if req.Pattern == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pattern is required"})
		return
	}
	switch req.Kind {
	case blocklist.KindFilename, blocklist.KindSegment, blocklist.KindRegex, blocklist.KindAllow:
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "kind must be one of filename, segment, regex, allow",
		})
		return
	}
	if req.Score < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "score cannot be negative"})
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	p := blocklist.Pattern{
		Kind: req.Kind, Pattern: req.Pattern, Score: req.Score,
		Rule: req.Rule, Enabled: enabled, Note: req.Note,
	}
	if _, errs := blocklist.Compile([]blocklist.Pattern{p}); len(errs) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": errs[0].Error()})
		return
	}

	if err := s.db.UpsertBlocklistPattern(r.Context(), p); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.auditLog(r, "security.pattern.upsert", "blocklist_pattern", req.Kind+":"+req.Pattern,
		map[string]any{"score": req.Score, "enabled": enabled})
	_ = s.triggerReload()
	writeJSON(w, http.StatusOK, p)
}

// handleDeleteBlockPattern removes an operator-added pattern. Builtin rows are
// refused with an explanation: deleting one would only last until the next
// boot, so the panel disables them instead.
func (s *Server) handleDeleteBlockPattern(w http.ResponseWriter, r *http.Request) {
	kind := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("kind")))
	pattern := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("pattern")))
	if kind == "" || pattern == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "kind and pattern are required"})
		return
	}

	ok, err := s.db.DeleteBlocklistPattern(r.Context(), kind, pattern)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "not found, or a built-in pattern. Built-in patterns can be disabled but not deleted, because the next restart would restore them.",
		})
		return
	}
	s.auditLog(r, "security.pattern.delete", "blocklist_pattern", kind+":"+pattern, nil)
	_ = s.triggerReload()
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// handleListBlocks returns the addresses currently refused.
func (s *Server) handleListBlocks(w http.ResponseWriter, r *http.Request) {
	blocks, err := s.db.ListActiveIPBlocks(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if blocks == nil {
		blocks = []blocklist.Block{}
	}
	writeJSON(w, http.StatusOK, blocks)
}

// handleDeleteBlock lifts one block. This is the correction path for a false
// positive, so it also clears the penalty ladder: an address released by the
// operator starts clean rather than serving double next time.
func (s *Server) handleDeleteBlock(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimSpace(r.PathValue("key"))
	if key == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key is required"})
		return
	}
	ok, err := s.db.DeleteIPBlock(r.Context(), key)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such block"})
		return
	}
	s.auditLog(r, "security.block.release", "ip_block", key, nil)
	_ = s.triggerReload()
	writeJSON(w, http.StatusOK, map[string]bool{"released": true})
}

// handleFlushBlocks releases everything. The panic button: reached for when a
// block is cutting real customer traffic and there is no time to work out which
// one.
func (s *Server) handleFlushBlocks(w http.ResponseWriter, r *http.Request) {
	n, err := s.db.FlushIPBlocks(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.auditLog(r, "security.block.flush", "ip_block", "", map[string]any{"released": n})
	_ = s.triggerReload()
	writeJSON(w, http.StatusOK, map[string]int{"released": n})
}
