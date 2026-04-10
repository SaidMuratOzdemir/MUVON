package router

import (
	"io/fs"
	"net/http"
	"strings"

	"muvon/internal/config"
	"muvon/internal/health"
	"muvon/internal/middleware"
	"muvon/internal/proxy"
)

type Router struct {
	proxyHandler *proxy.Handler
	configHolder *config.Holder
	frontendFS   fs.FS
	adminDomain  string
	adminHandler http.Handler
}

// New creates a Router. If adminDomain is non-empty, requests to that domain
// on :443 are served by adminHandler instead of the proxy.
func New(ch *config.Holder, logSink proxy.LogSink, transport http.RoundTripper, hm *health.Manager, inspector proxy.Inspector, instanceTracker proxy.InstanceTracker, frontendFS fs.FS, adminDomain string, adminHandler http.Handler) *Router {
	return &Router{
		proxyHandler: proxy.NewHandler(ch, logSink, transport, hm, inspector, instanceTracker),
		configHolder: ch,
		frontendFS:   frontendFS,
		adminDomain:  strings.ToLower(adminDomain),
		adminHandler: adminHandler,
	}
}

// ProxyHandler returns the underlying proxy handler for additional configuration.
func (rt *Router) ProxyHandler() *proxy.Handler {
	return rt.proxyHandler
}

func (rt *Router) Handler() http.Handler {
	// Ana proxy handler + middleware zinciri
	proxy := middleware.Recovery(middleware.SecurityHeaders(middleware.Gzip(rt.proxyHandler)))

	if rt.adminDomain == "" || rt.adminHandler == nil {
		return proxy
	}

	// adminDomain set edilmişse Host'a göre yönlendir
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		// port varsa sil (örn. "muvon.example.com:443" → "muvon.example.com")
		if i := strings.LastIndex(host, ":"); i != -1 {
			host = host[:i]
		}
		if host == rt.adminDomain {
			rt.adminHandler.ServeHTTP(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}
