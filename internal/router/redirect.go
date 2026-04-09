package router

import (
	"fmt"
	"net/http"
	"strings"

	"muvon/internal/config"
)

// HTTPSRedirectHandler redirects all HTTP traffic to HTTPS.
func HTTPSRedirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := fmt.Sprintf("https://%s%s", stripPort(r.Host), r.URL.RequestURI())
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

// ForceHTTPSHandler redirects to HTTPS when:
//   - the matched host has force_https=true, OR
//   - the host matches adminDomain (admin panel is always HTTPS-only)
//
// Other hosts return 404 on HTTP since we don't serve plain-HTTP content.
func ForceHTTPSHandler(ch *config.Holder, adminDomain string) http.Handler {
	adminDomain = strings.ToLower(adminDomain)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if i := strings.LastIndex(host, ":"); i != -1 {
			host = host[:i]
		}
		host = strings.ToLower(host)
		if adminDomain != "" && host == adminDomain {
			target := fmt.Sprintf("https://%s%s", host, r.URL.RequestURI())
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
		cfg := ch.Get()
		if hc, ok := cfg.Hosts[host]; ok && hc.Host.ForceHTTPS {
			target := fmt.Sprintf("https://%s%s", host, r.URL.RequestURI())
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
		http.NotFound(w, r)
	})
}

func stripPort(host string) string {
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
		if host[i] < '0' || host[i] > '9' {
			return host
		}
	}
	return host
}
