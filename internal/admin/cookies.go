package admin

import (
	"net/http"
	"time"
)

// Cookie names.
//
// The __Host- prefix is a browser-enforced contract: cookies with this prefix
// MUST be Secure, MUST have Path=/, and MUST NOT have a Domain attribute. That
// makes them impossible to forge from a parent/sibling domain, which matters
// because the admin panel shares an origin with user-controlled hosts.
//
// The refresh cookie deliberately scopes itself to /api/auth so it is never
// sent to non-auth endpoints — even if an XSS or upstream leak reads response
// cookies, the refresh token is already out of reach for most of the app.
// Because Path=/api/auth violates the __Host- contract, we use a plain name
// for the refresh cookie and keep the Secure/HttpOnly/SameSite flags.
const (
	cookieAccess  = "__Host-muvon_access"
	cookieRefresh = "muvon_refresh"
	cookieCSRF    = "muvon_csrf"

	refreshCookiePath = "/api/auth"
)

// setAccessCookie writes the short-lived access JWT. MaxAge is kept in sync
// with the JWT exp claim — the browser drops it at the same time the server
// would reject it.
func setAccessCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieAccess,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// setRefreshCookie writes the long-lived refresh token. Path is limited so the
// token never rides on routine API traffic.
func setRefreshCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieRefresh,
		Value:    token,
		Path:     refreshCookiePath,
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// setCSRFCookie writes the double-submit CSRF token. This cookie is NOT
// HttpOnly — the SPA reads it via document.cookie and echoes the value in the
// X-CSRF-Token header on state-changing requests. The server then compares
// header vs cookie; a cross-site attacker can trigger the cookie being sent
// but cannot read it to populate the header.
func setCSRFCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieCSRF,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: false, // JS must read this
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearAuthCookies expires all three cookies on logout. MaxAge=-1 + empty
// value makes the browser delete them immediately.
func clearAuthCookies(w http.ResponseWriter) {
	clear := func(name, path string) {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     path,
			MaxAge:   -1,
			HttpOnly: name != cookieCSRF,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
	}
	clear(cookieAccess, "/")
	clear(cookieRefresh, refreshCookiePath)
	clear(cookieCSRF, "/")
}
