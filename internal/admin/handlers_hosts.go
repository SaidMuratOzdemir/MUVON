package admin

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"muvon/internal/db"
)

// validDomain kabul edilen hostname/domain formatını doğrular (RFC 1123).
// Wildcard alan adlarına (*.) izin verilir.
var validDomain = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^localhost$`)

func domainError(err error) string {
	s := err.Error()
	if strings.Contains(s, "duplicate") || strings.Contains(s, "unique") {
		return "A host with this domain already exists"
	}
	return "Failed to save host"
}

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.db.ListHosts(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if hosts == nil {
		hosts = []db.Host{}
	}
	writeJSON(w, http.StatusOK, hosts)
}

func (s *Server) handleCreateHost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain         string    `json:"domain"`
		IsActive       *bool     `json:"is_active"`
		ForceHTTPS     *bool     `json:"force_https"`
		TrustedProxies *[]string `json:"trusted_proxies"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.Domain = strings.ToLower(strings.TrimSpace(req.Domain))
	if req.Domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain is required"})
		return
	}
	if !validDomain.MatchString(req.Domain) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain format (e.g. example.com)"})
		return
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	forceHTTPS := false
	if req.ForceHTTPS != nil {
		forceHTTPS = *req.ForceHTTPS
	}
	trustedProxies := []string{}
	if req.TrustedProxies != nil {
		trustedProxies = *req.TrustedProxies
	}

	host, err := s.db.CreateHost(r.Context(), req.Domain, isActive, forceHTTPS, trustedProxies)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": domainError(err)})
		return
	}

	s.auditLog(r, "host.create", "host", strconv.Itoa(host.ID), map[string]any{"domain": host.Domain})
	if err := s.triggerReload(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "host created but config reload failed: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, host)
}

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}

	host, err := s.db.GetHost(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "host not found"})
		return
	}
	writeJSON(w, http.StatusOK, host)
}

func (s *Server) handleUpdateHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}

	var req struct {
		Domain          string    `json:"domain"`
		IsActive        *bool     `json:"is_active"`
		ForceHTTPS      *bool     `json:"force_https"`
		TrustedProxies  *[]string `json:"trusted_proxies"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	existing, err := s.db.GetHost(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "host not found"})
		return
	}

	domain := existing.Domain
	if req.Domain != "" {
		req.Domain = strings.ToLower(strings.TrimSpace(req.Domain))
		if !validDomain.MatchString(req.Domain) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain format (e.g. example.com)"})
			return
		}
		domain = req.Domain
	}
	isActive := existing.IsActive
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	forceHTTPS := existing.ForceHTTPS
	if req.ForceHTTPS != nil {
		forceHTTPS = *req.ForceHTTPS
	}
	trustedProxies := existing.TrustedProxies
	if req.TrustedProxies != nil {
		trustedProxies = *req.TrustedProxies
	}

	host, err := s.db.UpdateHost(r.Context(), id, domain, isActive, forceHTTPS, trustedProxies)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": domainError(err)})
		return
	}

	s.auditLog(r, "host.update", "host", strconv.Itoa(id), map[string]any{"domain": domain, "is_active": isActive, "force_https": forceHTTPS})
	if err := s.triggerReload(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "host updated but config reload failed: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, host)
}

func (s *Server) handleDeleteHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}

	if err := s.db.DeleteHost(r.Context(), id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "host not found"})
		return
	}

	s.auditLog(r, "host.delete", "host", strconv.Itoa(id), nil)
	if err := s.triggerReload(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "host deleted but config reload failed: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
