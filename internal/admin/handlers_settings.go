package admin

import (
	"encoding/json"
	"net/http"
	"strings"

	"muvon/internal/db"
)

// secretKeys are settings that should be masked in GET responses (write-only behavior).
var secretKeys = map[string]bool{
	"jwt_secret":             true,
	"alerting_smtp_password": true,
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.db.GetAllSettings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Mask secret fields: return "***" if set, "" if empty
	for key := range secretKeys {
		raw, ok := settings[key]
		if !ok {
			continue
		}
		var val string
		json.Unmarshal(raw, &val)
		if val != "" {
			settings[key] = json.RawMessage(`"********"`)
		}
	}

	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) handleUpdateSetting(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if key == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key is required"})
		return
	}

	var req struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	// Normalize string-typed values at the boundary. Pasting from a docs page
	// or another tab routinely smuggles a trailing newline or leading space,
	// which then silently breaks features whose downstream consumer reads the
	// literal value (path, regex, hostname). Trim on read exists too, but we
	// also clean on write so the stored value matches what the admin sees.
	if trimmed, ok := trimJSONString(req.Value); ok {
		req.Value = trimmed
	}

	// For secret keys, don't accept the masked placeholder back
	if secretKeys[key] {
		var val string
		if json.Unmarshal(req.Value, &val) == nil && val == "********" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot save masked placeholder value"})
			return
		}
	}

	// Encrypt secret values before persisting to DB
	if secretKeys[key] && s.secretBox.HasKey() {
		var plainVal string
		if json.Unmarshal(req.Value, &plainVal) == nil && plainVal != "" {
			encrypted, err := s.secretBox.Encrypt(plainVal)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "encryption failed"})
				return
			}
			encJSON, _ := json.Marshal(encrypted)
			req.Value = encJSON
		}
	}

	if err := s.db.SetSetting(r.Context(), key, req.Value); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Audit log — mask secret values
	auditValue := string(req.Value)
	if secretKeys[key] {
		auditValue = "********"
	}
	s.auditLog(r, "update_setting", "setting", key, map[string]string{"value": auditValue})

	if err := s.triggerReload(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "setting updated but config reload failed: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// trimJSONString peels a JSON-encoded scalar string, trims it, and re-encodes.
// Returns ok=false for non-string JSON values (numbers, booleans, objects) so
// the caller leaves them untouched.
func trimJSONString(raw json.RawMessage) (json.RawMessage, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return raw, false
	}
	trimmed := strings.TrimSpace(s)
	if trimmed == s {
		return raw, true
	}
	out, err := json.Marshal(trimmed)
	if err != nil {
		return raw, true
	}
	return out, true
}

func (s *Server) handleListCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := s.db.ListCerts(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if certs == nil {
		certs = []db.TLSCert{}
	}
	writeJSON(w, http.StatusOK, certs)
}

func (s *Server) handleUploadCert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain  string `json:"domain"`
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Domain == "" || req.CertPEM == "" || req.KeyPEM == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain, cert_pem and key_pem are required"})
		return
	}
	req.Domain = strings.ToLower(strings.TrimSpace(req.Domain))

	// Sertifikayı parse edip son kullanma tarihini bul
	certBytes := []byte(req.CertPEM)
	keyBytes := []byte(req.KeyPEM)

	// tls.X509KeyPair ile validasyon
	_, err := tlsX509KeyPair(certBytes, keyBytes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid certificate or key: " + err.Error()})
		return
	}

	expiresAt := extractCertExpiry(certBytes)

	if err := s.db.UpsertCert(r.Context(), req.Domain, certBytes, keyBytes, "manual", expiresAt); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if s.tlsManager != nil {
		s.tlsManager.InvalidateCache(req.Domain)
	}

	writeJSON(w, http.StatusCreated, map[string]string{"status": "ok", "domain": req.Domain})
}

func (s *Server) handleDeleteCert(w http.ResponseWriter, r *http.Request) {
	id := 0
	if v := r.PathValue("id"); v != "" {
		var err error
		id, err = parseInt(v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
	}

	domain, err := s.db.DeleteCert(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "certificate not found"})
		return
	}
	if s.tlsManager != nil {
		s.tlsManager.InvalidateCache(domain)
	}

	w.WriteHeader(http.StatusNoContent)
}
