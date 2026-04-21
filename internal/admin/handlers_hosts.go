package admin

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"muvon/internal/db"
)

// maskHostSecret replaces the encrypted ciphertext in API responses with
// a fixed placeholder when set, so the admin UI can tell "secret is set"
// from "secret is empty" without ever seeing the ciphertext itself.
func maskHostSecret(h db.Host) db.Host {
	if h.JWTSecret != "" {
		h.JWTSecret = "********"
	}
	return h
}

// buildHostJWT gathers and encrypts the JWT fields from a create payload.
// An empty secret string means the admin didn't provide one — we store
// empty, which triggers the decode-only path in the pipeline extractor.
func (s *Server) buildHostJWT(enabled *bool, mode, claims, plaintextSecret string) (db.HostJWT, error) {
	jwt := db.HostJWT{Mode: mode, Claims: claims}
	if enabled != nil {
		jwt.Enabled = *enabled
	}
	if jwt.Mode == "" {
		jwt.Mode = "verify"
	}
	if plaintextSecret != "" {
		enc, err := s.secretBox.Encrypt(plaintextSecret)
		if err != nil {
			return jwt, err
		}
		jwt.Secret = enc
	}
	return jwt, nil
}

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
	// Response must never leak ciphertext — mask each row before writing.
	for i := range hosts {
		hosts[i] = maskHostSecret(hosts[i])
	}
	writeJSON(w, http.StatusOK, hosts)
}

func (s *Server) handleCreateHost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain             string    `json:"domain"`
		IsActive           *bool     `json:"is_active"`
		ForceHTTPS         *bool     `json:"force_https"`
		TrustedProxies     *[]string `json:"trusted_proxies"`
		JWTIdentityEnabled *bool     `json:"jwt_identity_enabled"`
		JWTIdentityMode    string    `json:"jwt_identity_mode"`
		JWTClaims          string    `json:"jwt_claims"`
		JWTSecret          string    `json:"jwt_secret"` // plaintext in; encrypted at rest
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
	jwt, err := s.buildHostJWT(req.JWTIdentityEnabled, req.JWTIdentityMode, req.JWTClaims, req.JWTSecret)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "jwt secret encryption failed"})
		return
	}

	host, err := s.db.CreateHost(r.Context(), req.Domain, isActive, forceHTTPS, trustedProxies, jwt)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": domainError(err)})
		return
	}
	host = maskHostSecret(host)

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
	writeJSON(w, http.StatusOK, maskHostSecret(host))
}

func (s *Server) handleUpdateHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}

	var req struct {
		Domain             string    `json:"domain"`
		IsActive           *bool     `json:"is_active"`
		ForceHTTPS         *bool     `json:"force_https"`
		TrustedProxies     *[]string `json:"trusted_proxies"`
		JWTIdentityEnabled *bool     `json:"jwt_identity_enabled"`
		JWTIdentityMode    string    `json:"jwt_identity_mode"`
		JWTClaims          string    `json:"jwt_claims"`
		// Plaintext when rotating the secret. Empty string means "leave as
		// it is" so the UI can PATCH-style update other fields without
		// re-asking for the secret every time.
		JWTSecret          string    `json:"jwt_secret"`
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
	// JWT fields: fall back to existing values when the request omits them.
	// An empty secret string in the body means "keep existing" — matches how
	// the admin UI hides the secret after save.
	jwtEnabled := existing.JWTIdentityEnabled
	if req.JWTIdentityEnabled != nil {
		jwtEnabled = *req.JWTIdentityEnabled
	}
	jwtMode := existing.JWTIdentityMode
	if req.JWTIdentityMode != "" {
		jwtMode = req.JWTIdentityMode
	}
	jwtClaims := existing.JWTClaims
	if req.JWTClaims != "" {
		jwtClaims = req.JWTClaims
	}
	jwtSecret := existing.JWTSecret // already-encrypted ciphertext
	if req.JWTSecret != "" {
		enc, err := s.secretBox.Encrypt(req.JWTSecret)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "jwt secret encryption failed"})
			return
		}
		jwtSecret = enc
	}

	host, err := s.db.UpdateHost(r.Context(), id, domain, isActive, forceHTTPS, trustedProxies, db.HostJWT{
		Enabled: jwtEnabled,
		Mode:    jwtMode,
		Claims:  jwtClaims,
		Secret:  jwtSecret,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": domainError(err)})
		return
	}
	host = maskHostSecret(host)

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
