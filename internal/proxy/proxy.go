package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"muvon/internal/config"
	"muvon/internal/health"
	"muvon/internal/logger"
	"muvon/internal/middleware"
	"muvon/internal/waf"
)

// Per-route rate limiter registry (routeID → *middleware.RateLimiter)
var routeLimiters sync.Map

// Per-route round-robin counter (routeID → *atomic.Uint64)
var routeCounters sync.Map

type Handler struct {
	configHolder    *config.Holder
	logSink         LogSink
	transport       http.RoundTripper
	maxBodySize     int
	enableCapture   bool
	inspector       Inspector
	healthMgr       *health.Manager
	instanceTracker InstanceTracker
}

func NewHandler(ch *config.Holder, logSink LogSink, transport http.RoundTripper, hm *health.Manager, inspector Inspector, instanceTracker InstanceTracker) *Handler {
	cfg := ch.Get()
	return &Handler{
		configHolder:    ch,
		logSink:         logSink,
		transport:       transport,
		maxBodySize:     cfg.Global.MaxBodyCaptureSize,
		enableCapture:   cfg.Global.EnableBodyCapture,
		inspector:       inspector,
		healthMgr:       hm,
		instanceTracker: instanceTracker,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	cfg := h.configHolder.Get()

	host := stripPort(r.Host)
	hc, ok := cfg.Hosts[host]
	if !ok {
		http.Error(w, "unknown host", http.StatusBadGateway)
		return
	}

	route := matchRoute(hc.Routes, r.URL.Path)
	if route == nil {
		http.Error(w, "no matching route", http.StatusNotFound)
		return
	}

	// Signed file serve — validate token and serve directly, no backend call.
	if route.Route.AccelRoot != nil && route.Route.AccelSignedSecret != nil {
		serveSignedAccel(w, r, *route.Route.AccelRoot, *route.Route.AccelSignedSecret)
		return
	}

	switch route.Route.RouteType {
	case "proxy":
		h.serveProxy(w, r, route, hc, start)
	case "redirect":
		h.serveRedirect(w, r, route)
	case "static":
		h.serveStatic(w, r, route)
	default:
		http.Error(w, "invalid route type", http.StatusInternalServerError)
	}
}

func (h *Handler) serveProxy(w http.ResponseWriter, r *http.Request, route *config.RouteRule, hc *config.HostConfig, start time.Time) {
	cfg := h.configHolder.Get()
	enableCapture := cfg.Global.EnableBodyCapture
	maxBodySize := cfg.Global.MaxBodyCaptureSize

	// CORS — handle before any other processing so preflight returns immediately.
	if route.Route.CORSEnabled {
		if applyCORSHeaders(w, r, route.Route) {
			return // preflight fully handled
		}
	}

	// Per-route request body size limit.
	if route.Route.MaxBodyBytes > 0 {
		if r.ContentLength > route.Route.MaxBodyBytes {
			http.Error(w, "413 Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, route.Route.MaxBodyBytes)
	}

	// Per-route backend timeout — evaluated before isUpgrade below; skip for WebSocket/SSE.
	// isUpgrade is re-used in the capture section; keep this consistent.
	isUpgrade := r.Header.Get("Upgrade") != ""
	if route.Route.TimeoutSeconds > 0 && !isUpgrade {
		var cancel context.CancelFunc
		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(route.Route.TimeoutSeconds)*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
	}

	// Generate time-ordered UUID v7 for this request — flows to SIEM and muWAF MongoDB
	reqID := uuid.Must(uuid.NewV7()).String()
	r.Header.Set("X-Request-ID", reqID)

	backend := pickBackend(route)
	if backend.URL == "" {
		http.Error(w, "no backend configured", http.StatusBadGateway)
		return
	}
	if backend.InstanceID != "" && h.instanceTracker != nil {
		r.Header.Set("X-Muvon-Deploy-Instance", backend.InstanceID)
		h.instanceTracker.AdjustDeployInstanceInFlight(r.Context(), backend.InstanceID, 1)
		defer h.instanceTracker.AdjustDeployInstanceInFlight(context.Background(), backend.InstanceID, -1)
	}

	target, err := url.Parse(backend.URL)
	if err != nil {
		http.Error(w, "invalid backend URL", http.StatusBadGateway)
		return
	}

	// Request header'larını kaydet
	reqHeaders := captureHeaders(r.Header)

	// Trusted-proxy-aware client IP (used for rate limiting, WAF, logging).
	ip := clientIPFor(r, hc.Host.TrustedProxies)

	// Akıllı body yakalama:
	// - GET/HEAD/OPTIONS/static route → body okuma (sadece header/path/IP gönder)
	// - POST/PUT/PATCH → body oku (max 64KB WAF için, enableCapture limiti SIEM için)
	var reqCapture *CapturedBody
	wafNeedsBody := route.Route.WafEnabled && h.inspector != nil && methodCarriesBody(r.Method)
	needBody := enableCapture || wafNeedsBody
	if needBody {
		r, reqCapture = CaptureRequestBody(r, maxBodySize)
	}

	// Per-route rate limiting
	if route.Route.RateLimitRPS > 0 {
		rl := getRouteLimiter(route.Route.ID, route.Route.RateLimitRPS, route.Route.RateLimitBurst)
		if !rl.Allow(ip) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
			return
		}
	}

	// WAF inspection — synchronous (in-process or remote gRPC)
	var wafResult waf.InspectResult
	if route.Route.WafEnabled && h.inspector != nil && !isWafExcluded(r.URL.Path, route.Route.WafExcludePaths) {
		// Body sadece POST/PUT/PATCH gibi payload taşıyan method'larda gönderilir.
		// GET/HEAD/OPTIONS için body nil — WAF sadece path, query, header inceler.
		var bodyBytes []byte
		if wafNeedsBody && reqCapture != nil {
			bodyBytes = reqCapture.Data
		}

		wafResult = h.inspector.Inspect(r.Context(), waf.InspectRequest{
			RequestID:     reqID,
			ClientIP:      ip,
			Host:          stripPort(r.Host),
			Method:        r.Method,
			Path:          r.URL.Path,
			RawQuery:      r.URL.RawQuery,
			Headers:       r.Header,
			Body:          bodyBytes,
			ContentType:   r.Header.Get("Content-Type"),
			RouteID:       route.Route.ID,
			DetectionOnly: route.Route.WafDetectionOnly,
		})

		if !wafResult.DetectionOnly {
			switch wafResult.Action {
			case waf.ActionBlock, waf.ActionTempBan, waf.ActionBan:
				http.Error(w, "Forbidden", http.StatusForbidden)
				if route.Route.LogEnabled && h.logSink != nil {
					wafEntry := logger.Entry{
						RequestID:      reqID,
						Timestamp:      start,
						Host:           stripPort(r.Host),
						ClientIP:       ip,
						Method:         r.Method,
						Path:           r.URL.Path,
						QueryString:    r.URL.RawQuery,
						RequestHeaders: reqHeaders,
						ResponseStatus: http.StatusForbidden,
						ResponseTimeMs: int(time.Since(start).Milliseconds()),
						UserAgent:      r.UserAgent(),
						WafBlocked:     true,
						WafBlockReason: wafResult.BlockReason,
						WafScore:       wafResult.RequestScore,
						WafAction:      string(wafResult.Action),
					}
					if reqCapture != nil {
						wafEntry.RequestBody = reqCapture.Data
						wafEntry.RequestSize = reqCapture.Size
						wafEntry.IsRequestTruncated = reqCapture.Truncated
					}
					h.logSink.Send(wafEntry)
				}
				return
			}
		}
	}

	// Circuit breaker check
	if h.healthMgr != nil && !h.healthMgr.Allow(backend.URL) {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	// WebSocket/SSE kontrolu
	isSSE := strings.Contains(r.Header.Get("Accept"), "text/event-stream")
	skipResponseCapture := isUpgrade || isSSE

	// Response capture
	var rc *ResponseCapture
	if enableCapture && !skipResponseCapture {
		rc = NewResponseCapture(w, maxBodySize, false)
		w = rc
	}

	// X-Accel-Redirect: wrap writer to intercept backend redirect and serve local file
	if route.Route.AccelRoot != nil && !skipResponseCapture {
		w = newAccelWriter(w, r, *route.Route.AccelRoot)
	}

	// Proxy
	stripPrefix := ""
	if route.Route.StripPrefix {
		stripPrefix = route.PathPrefix
	}

	hm := h.healthMgr
	routeSnapshot := route.Route
	rp := &httputil.ReverseProxy{
		Director:      Director(target, stripPrefix, routeSnapshot, ip),
		Transport:     h.transport,
		FlushInterval: -1, // SSE desteği: anında flush
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if hm != nil {
				hm.RecordFailure(backend.URL)
			}
			if routeSnapshot.ErrorPage5xx != nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusBadGateway)
				fmt.Fprint(w, *routeSnapshot.ErrorPage5xx)
				return
			}
			proxyErrorHandler(w, r, err)
		},
		ModifyResponse: modifyResponse(routeSnapshot),
	}

	rp.ServeHTTP(w, r)

	// Record backend success for circuit breaker
	if hm != nil {
		hm.RecordSuccess(backend.URL)
	}

	// Log kaydı — route log_enabled=false ise pipeline'a gönderme
	if !route.Route.LogEnabled {
		return
	}

	elapsed := time.Since(start)
	entry := logger.Entry{
		RequestID:      reqID,
		Timestamp:      start,
		Host:           stripPort(r.Host),
		ClientIP:       ip,
		Method:         r.Method,
		Path:           r.URL.Path,
		QueryString:    r.URL.RawQuery,
		RequestHeaders: reqHeaders,
		ResponseTimeMs: int(elapsed.Milliseconds()),
		UserAgent:      r.UserAgent(),
	}

	if reqCapture != nil {
		entry.RequestBody = reqCapture.Data
		entry.RequestSize = reqCapture.Size
		entry.IsRequestTruncated = reqCapture.Truncated
	}

	if rc != nil {
		entry.ResponseStatus = rc.StatusCode()
		entry.ResponseHeaders = rc.CapturedHeaders()
		respBody := rc.CapturedBody()
		entry.ResponseBody = respBody.Data
		entry.ResponseSize = respBody.Size
		entry.IsResponseTruncated = respBody.Truncated
	}

	if h.logSink != nil {
		h.logSink.Send(entry)
	}
}

func (h *Handler) serveRedirect(w http.ResponseWriter, r *http.Request, route *config.RouteRule) {
	if route.Route.RedirectURL == nil {
		http.Error(w, "no redirect URL", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, *route.Route.RedirectURL, http.StatusMovedPermanently)
}

func (h *Handler) serveStatic(w http.ResponseWriter, r *http.Request, route *config.RouteRule) {
	if route.Route.StaticRoot == nil {
		http.Error(w, "no static root", http.StatusInternalServerError)
		return
	}

	if route.Route.StripPrefix {
		p := strings.TrimPrefix(r.URL.Path, route.PathPrefix)
		if p == "" {
			p = "/"
		}
		u := *r.URL
		u.Path = p
		r2 := new(http.Request)
		*r2 = *r
		r2.URL = &u
		r = r2
	}

	fs := noListFS{http.Dir(*route.Route.StaticRoot)}
	http.FileServer(fs).ServeHTTP(w, r)
}

// noListFS wraps http.FileSystem to disable directory listing.
// If a directory is requested without an index.html, it returns 404.
type noListFS struct{ http.FileSystem }

func (fs noListFS) Open(name string) (http.File, error) {
	f, err := fs.FileSystem.Open(name)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if fi.IsDir() {
		idx, err := fs.FileSystem.Open(strings.TrimSuffix(name, "/") + "/index.html")
		if err != nil {
			f.Close()
			return nil, os.ErrNotExist
		}
		idx.Close()
	}
	return f, nil
}

func matchRoute(routes []config.RouteRule, path string) *config.RouteRule {
	var best *config.RouteRule
	bestLen := -1

	for i := range routes {
		prefix := routes[i].PathPrefix
		if strings.HasPrefix(path, prefix) && len(prefix) > bestLen {
			best = &routes[i]
			bestLen = len(prefix)
		}
	}
	return best
}

func proxyErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("proxy error", "host", r.Host, "path", r.URL.Path, "error", err)
	w.WriteHeader(http.StatusBadGateway)
	fmt.Fprintf(w, "proxy error: %v", err)
}

func stripPort(host string) string {
	if i := strings.LastIndex(host, ":"); i != -1 {
		return host[:i]
	}
	return host
}

// clientIPFor returns the real client IP, trusting X-Forwarded-For only when
// the direct connection (RemoteAddr) is in the trusted proxies list.
// If trustedProxies is empty, falls back to RemoteAddr (conservative default).
func clientIPFor(r *http.Request, trustedProxies []string) string {
	remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)
	if remoteHost == "" {
		remoteHost = r.RemoteAddr
	}

	if len(trustedProxies) > 0 && isTrustedProxy(remoteHost, trustedProxies) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Leftmost entry is the original client.
			if i := strings.Index(xff, ","); i != -1 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}

	return remoteHost
}

// cidrEntry caches a parsed CIDR or nil if the entry was not a valid CIDR.
type cidrEntry struct{ network *net.IPNet }

var cidrCache sync.Map // string → cidrEntry

func parseCIDRCached(entry string) *net.IPNet {
	if v, ok := cidrCache.Load(entry); ok {
		return v.(cidrEntry).network
	}
	_, network, err := net.ParseCIDR(entry)
	e := cidrEntry{} // nil .network means parse failed
	if err == nil {
		e.network = network
	}
	v, _ := cidrCache.LoadOrStore(entry, e)
	return v.(cidrEntry).network
}

// isTrustedProxy checks whether ip is in the trusted proxies list.
// Entries may be plain IPs or CIDR ranges; CIDR parsing is cached.
func isTrustedProxy(ip string, trusted []string) bool {
	parsed := net.ParseIP(ip)
	for _, entry := range trusted {
		if strings.Contains(entry, "/") {
			if network := parseCIDRCached(entry); network != nil && parsed != nil && network.Contains(parsed) {
				return true
			}
		} else if entry == ip {
			return true
		}
	}
	return false
}

func captureHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

type selectedBackend struct {
	URL        string
	InstanceID string
}

// pickBackend selects a backend URL for the route.
// Managed routes only use active deployment instances. Legacy routes keep
// the existing backend_urls/backend_url behavior.
func pickBackend(route *config.RouteRule) selectedBackend {
	if len(route.ManagedBackends) > 0 {
		v, _ := routeCounters.LoadOrStore(route.Route.ID, new(atomic.Uint64))
		idx := v.(*atomic.Uint64).Add(1) % uint64(len(route.ManagedBackends))
		backend := route.ManagedBackends[idx]
		return selectedBackend{URL: backend.BackendURL, InstanceID: backend.InstanceID}
	}
	urls := route.Route.BackendURLs
	if len(urls) == 0 {
		if route.Route.BackendURL == nil {
			return selectedBackend{}
		}
		return selectedBackend{URL: *route.Route.BackendURL}
	}
	v, _ := routeCounters.LoadOrStore(route.Route.ID, new(atomic.Uint64))
	idx := v.(*atomic.Uint64).Add(1) % uint64(len(urls))
	return selectedBackend{URL: urls[idx]}
}

// getRouteLimiter returns (or creates) a per-route RateLimiter.
func getRouteLimiter(routeID, rps, burst int) *middleware.RateLimiter {
	if v, ok := routeLimiters.Load(routeID); ok {
		return v.(*middleware.RateLimiter)
	}
	// Use rps as requests per second: window = 1s, capacity = burst (or rps if burst==0)
	cap := burst
	if cap <= 0 {
		cap = rps
	}
	rl := middleware.NewRateLimiter(cap, time.Second)
	actual, _ := routeLimiters.LoadOrStore(routeID, rl)
	return actual.(*middleware.RateLimiter)
}

// ClearRouteLimiters evicts all cached limiters (call on config reload).
func ClearRouteLimiters() {
	routeLimiters.Range(func(k, _ any) bool {
		routeLimiters.Delete(k)
		return true
	})
}

// methodCarriesBody returns true for HTTP methods that typically carry a request body.
// GET, HEAD, OPTIONS, TRACE, CONNECT do not carry meaningful body for WAF inspection.
func methodCarriesBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// isWafExcluded returns true if reqPath matches any glob pattern in patterns.
func isWafExcluded(reqPath string, patterns []string) bool {
	for _, pat := range patterns {
		if matched, _ := path.Match(pat, reqPath); matched {
			return true
		}
	}
	return false
}
