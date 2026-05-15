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
//
// selfKind+selfAgentID identify which MUVON instance this router belongs to,
// so the proxy can reject misdirected traffic (a request that landed on the
// wrong terminator returns 421 Misdirected Request instead of being silently
// served). Central passes ("central", "") and agents pass ("agent", agentID).
// Empty selfKind disables enforcement — used by callers that don't yet have
// host ownership wiring.
func New(ch *config.Holder, logSink proxy.LogSink, transport http.RoundTripper, hm *health.Manager, instanceTracker proxy.InstanceTracker, frontendFS fs.FS, adminDomain string, adminHandler http.Handler, selfKind, selfAgentID string) *Router {
	return &Router{
		proxyHandler: proxy.NewHandler(ch, logSink, transport, hm, instanceTracker, selfKind, selfAgentID),
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
