package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
)

const csrfHeader = "X-CSRF-Token"

// generateCSRFToken produces 32 bytes of entropy, base64url-encoded. Unlike
// the refresh token this value is not stored — it is merely a shared secret
// between the cookie (set by the server) and the X-CSRF-Token header (sent by
// the SPA). Anyone who can read both is same-origin by definition.
func generateCSRFToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// csrfMiddleware enforces the double-submit cookie pattern for state-changing
// methods. Safe methods (GET/HEAD/OPTIONS) and the paths listed in bypass are
// never checked — either they cannot be triggered cross-site to cause harm or
// they run before the CSRF cookie even exists (login/setup).
//
// Both the cookie and the header must be present AND equal. A missing cookie
// or header is a 403; a mismatched pair is a 403. Using subtle.ConstantTime
// keeps us constant-time against a (tiny) timing oracle.
func csrfMiddleware(bypass map[string]bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isSafeMethod(r.Method) || bypass[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			cookie, err := r.Cookie(cookieCSRF)
			if err != nil || cookie.Value == "" {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf cookie missing"})
				return
			}
			header := r.Header.Get(csrfHeader)
			if header == "" {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf header missing"})
				return
			}
			if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf mismatch"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}
