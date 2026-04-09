package proxy

import (
	"net/http"
	"strconv"
	"strings"

	"muvon/internal/db"
)

// applyCORSHeaders sets CORS response headers based on route config.
// Returns true if the request was a preflight OPTIONS that was fully handled.
func applyCORSHeaders(w http.ResponseWriter, r *http.Request, route db.Route) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}

	// Determine allowed origin to reflect.
	allowedOrigin := resolveOrigin(origin, route.CORSOrigins)
	if allowedOrigin == "" {
		return false
	}

	h := w.Header()
	h.Set("Access-Control-Allow-Origin", allowedOrigin)
	if allowedOrigin != "*" {
		h.Add("Vary", "Origin")
	}
	if route.CORSCredentials {
		h.Set("Access-Control-Allow-Credentials", "true")
	}

	// Preflight
	if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
		h.Set("Access-Control-Allow-Methods", route.CORSMethods)
		h.Set("Access-Control-Allow-Headers", route.CORSHeaders)
		if route.CORSMaxAge > 0 {
			h.Set("Access-Control-Max-Age", strconv.Itoa(route.CORSMaxAge))
		}
		w.WriteHeader(http.StatusNoContent)
		return true
	}

	return false
}

// resolveOrigin returns the value to use for Access-Control-Allow-Origin.
// Returns "" if the request origin is not allowed.
func resolveOrigin(requestOrigin, allowedOrigins string) string {
	if allowedOrigins == "*" {
		return "*"
	}
	for _, o := range strings.Split(allowedOrigins, ",") {
		if strings.TrimSpace(o) == requestOrigin {
			return requestOrigin
		}
	}
	return ""
}
