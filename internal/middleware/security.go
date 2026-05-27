package middleware

import "net/http"

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// SAMEORIGIN (not DENY): the edge fronts apps that legitimately embed
		// their own same-origin content — PDF/image previews via <object>/<iframe>
		// over served /media files. DENY blocked even same-origin framing and
		// could not be overridden per route; SAMEORIGIN still blocks cross-site
		// clickjacking. A backend that needs stricter framing sets its own header.
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}
