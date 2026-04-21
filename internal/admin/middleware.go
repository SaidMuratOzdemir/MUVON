package admin

import (
	"context"
	"net/http"
)

type contextKey string

const userIDKey contextKey = "user_id"
const usernameKey contextKey = "username"

// authMiddleware validates the access cookie and populates user_id / username
// on the request context. Cookie-only: the old Authorization: Bearer header
// path is gone — CSRF protection relies on the browser sending the cookie
// automatically, not on the caller choosing when to attach it.
//
// SSE endpoints work the same way: EventSource sends same-origin cookies by
// default, so no ?token= query parameter is needed.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieAccess)
		if err != nil || cookie.Value == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
			return
		}
		claims, err := s.auth.ValidateAccessToken(cookie.Value)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired session"})
			return
		}
		ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)
		ctx = context.WithValue(ctx, usernameKey, claims.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// corsMiddleware allows credentialed requests from the admin panel. The panel
// is served from the same origin as the API, but the explicit CORS headers
// keep development setups (e.g. Vite dev server talking to a separate backend)
// working without surprises. Cookies are sent, so Access-Control-Allow-Origin
// cannot be "*" — mirror the request Origin instead.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token, X-Muvon-Signature-256, X-Hub-Signature-256")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
