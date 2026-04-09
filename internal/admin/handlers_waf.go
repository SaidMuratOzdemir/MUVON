package admin

import (
	"encoding/json"
	"net/http"
	"strconv"

	pb "muvon/proto/wafpb"
)

// --- WAF Rule Handlers (proxied to muWAF via gRPC) ---

func (s *Server) handleListWafRules(w http.ResponseWriter, r *http.Request) {
	if !s.requireWAF(w) {
		return
	}
	rules, err := s.wafClient.ListRules(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if rules == nil {
		rules = []*pb.Rule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handleGetWafRule(w http.ResponseWriter, r *http.Request) {
	if !s.requireWAF(w) {
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	rule, err := s.wafClient.GetRule(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) handleCreateWafRule(w http.ResponseWriter, r *http.Request) {
	if !s.requireWAF(w) {
		return
	}
	var req struct {
		Pattern     string `json:"pattern"`
		IsRegex     bool   `json:"is_regex"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Pattern == "" || req.Category == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pattern and category required"})
		return
	}
	if req.Severity <= 0 {
		req.Severity = 5
	}

	rule, err := s.wafClient.CreateRule(r.Context(), req.Pattern, req.Category, req.IsRegex, req.Severity, req.Description)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) handleUpdateWafRule(w http.ResponseWriter, r *http.Request) {
	if !s.requireWAF(w) {
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}

	var req struct {
		Pattern     string `json:"pattern"`
		IsRegex     bool   `json:"is_regex"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
		Description string `json:"description"`
		IsActive    bool   `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	rule, err := s.wafClient.UpdateRule(r.Context(), id, req.Pattern, req.Category, req.IsRegex, req.Severity, req.Description, req.IsActive)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) handleDeleteWafRule(w http.ResponseWriter, r *http.Request) {
	if !s.requireWAF(w) {
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	if err := s.wafClient.DeleteRule(r.Context(), id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleImportWafRules(w http.ResponseWriter, r *http.Request) {
	if !s.requireWAF(w) {
		return
	}
	var rules []struct {
		Pattern     string `json:"pattern"`
		IsRegex     bool   `json:"is_regex"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON array"})
		return
	}

	var pbRules []*pb.CreateRuleRequest
	for _, req := range rules {
		if req.Pattern == "" || req.Category == "" {
			continue
		}
		if req.Severity <= 0 {
			req.Severity = 5
		}
		pbRules = append(pbRules, &pb.CreateRuleRequest{
			Pattern:     req.Pattern,
			IsRegex:     req.IsRegex,
			Category:    req.Category,
			Severity:    int32(req.Severity),
			Description: req.Description,
		})
	}

	imported, err := s.wafClient.ImportRules(r.Context(), pbRules)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"imported": imported, "total": len(rules)})
}

// --- WAF IP Handlers ---

func (s *Server) handleListWafIPs(w http.ResponseWriter, r *http.Request) {
	if !s.requireWAF(w) {
		return
	}
	states, err := s.wafClient.ListIPStates(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if states == nil {
		states = []*pb.IPStateEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ips": states})
}

func (s *Server) handleBanIP(w http.ResponseWriter, r *http.Request) {
	if !s.requireWAF(w) {
		return
	}
	var req struct {
		IP       string `json:"ip"`
		Reason   string `json:"reason"`
		Duration int    `json:"duration_minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip required"})
		return
	}
	if req.Duration <= 0 {
		req.Duration = 60
	}
	if req.Reason == "" {
		req.Reason = "manual_ban"
	}

	if err := s.wafClient.BanIP(r.Context(), req.IP, req.Reason, req.Duration); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "banned", "ip": req.IP})
}

func (s *Server) handleUnbanIP(w http.ResponseWriter, r *http.Request) {
	if !s.requireWAF(w) {
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip required"})
		return
	}

	if err := s.wafClient.UnbanIP(r.Context(), req.IP); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "unbanned", "ip": req.IP})
}

func (s *Server) handleWhitelistIP(w http.ResponseWriter, r *http.Request) {
	if !s.requireWAF(w) {
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip required"})
		return
	}

	if err := s.wafClient.WhitelistIP(r.Context(), req.IP); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "whitelisted", "ip": req.IP})
}

func (s *Server) handleRemoveWhitelist(w http.ResponseWriter, r *http.Request) {
	if !s.requireWAF(w) {
		return
	}
	ip := r.PathValue("ip")
	if ip == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip required"})
		return
	}

	if err := s.wafClient.RemoveWhitelist(r.Context(), ip); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed", "ip": ip})
}

// --- WAF Exclusion Handlers ---

func (s *Server) handleListWafExclusions(w http.ResponseWriter, r *http.Request) {
	if !s.requireWAF(w) {
		return
	}
	exclusions, err := s.wafClient.ListExclusions(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if exclusions == nil {
		exclusions = []*pb.Exclusion{}
	}
	writeJSON(w, http.StatusOK, exclusions)
}

func (s *Server) handleCreateWafExclusion(w http.ResponseWriter, r *http.Request) {
	if !s.requireWAF(w) {
		return
	}
	var req struct {
		RouteID   int    `json:"route_id"`
		RuleID    int    `json:"rule_id"`
		Parameter string `json:"parameter"`
		Location  string `json:"location"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.RouteID == 0 || req.RuleID == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "route_id and rule_id required"})
		return
	}
	if req.Location == "" {
		req.Location = "all"
	}

	excl, err := s.wafClient.CreateExclusion(r.Context(), req.RuleID, req.RouteID, req.Location, req.Parameter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, excl)
}

func (s *Server) handleDeleteWafExclusion(w http.ResponseWriter, r *http.Request) {
	if !s.requireWAF(w) {
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	if err := s.wafClient.DeleteExclusion(r.Context(), id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "exclusion not found"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- WAF Events & Stats ---

func (s *Server) handleSearchWafEvents(w http.ResponseWriter, r *http.Request) {
	if !s.requireWAF(w) {
		return
	}
	q := r.URL.Query()
	clientIP := q.Get("client_ip")
	action := q.Get("action")
	host := q.Get("host")
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	resp, err := s.wafClient.SearchEvents(r.Context(), clientIP, action, host, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events": resp.Events,
		"total":  resp.Total,
		"limit":  limit,
		"offset": offset,
	})
}

func (s *Server) handleWafStats(w http.ResponseWriter, r *http.Request) {
	if !s.requireWAF(w) {
		return
	}
	stats, err := s.wafClient.GetStats(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}
