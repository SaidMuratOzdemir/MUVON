package admin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"muvon/internal/agentsvc"
	"muvon/internal/config"
	"muvon/internal/db"
	"muvon/internal/health"
	logclient "muvon/internal/logger/grpcclient"
	"muvon/internal/middleware"
	"muvon/internal/secret"
	tlspkg "muvon/internal/tls"
	wafclient "muvon/internal/waf/grpcclient"
)

type Server struct {
	db           *db.DB
	auth         *Auth
	configHolder *config.Holder
	secretBox    *secret.Box
	wafClient    *wafclient.RemoteInspector // nil = muWAF unavailable
	logClient    *logclient.RemoteLogSink   // nil = diaLOG unavailable
	tlsManager   *tlspkg.Manager
	healthMgr    *health.Manager
	agentSvc     *agentsvc.Service // nil = agent API disabled
	frontendFS   fs.FS
	startTime    time.Time
}

func NewServer(
	database *db.DB,
	jwtSecret string,
	ch *config.Holder,
	wc *wafclient.RemoteInspector,
	lc *logclient.RemoteLogSink,
	tlsMgr *tlspkg.Manager,
	hm *health.Manager,
	agentSvc *agentsvc.Service,
	frontendFS fs.FS,
) *Server {
	return &Server{
		db:           database,
		auth:         NewAuth(jwtSecret),
		configHolder: ch,
		secretBox:    ch.Box(),
		wafClient:    wc,
		logClient:    lc,
		tlsManager:   tlsMgr,
		healthMgr:    hm,
		agentSvc:     agentSvc,
		frontendFS:   frontendFS,
		startTime:    time.Now(),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	rl := middleware.NewRateLimiter(100, time.Minute)

	// Auth endpoints (rate limited, no JWT).
	// CSRF is enforced by a single middleware instance shared with the
	// protected api mux; login/setup/refresh are in the bypass list because
	// they establish or renew the cookie (and therefore cannot have a valid
	// CSRF pair yet). Logout is not bypassed — it is state-changing and
	// callable while a session is active.
	csrfMW := csrfMiddleware(map[string]bool{
		"/api/auth/login":   true,
		"/api/auth/setup":   true,
		"/api/auth/refresh": true,
	})

	authMux := http.NewServeMux()
	authMux.HandleFunc("POST /api/auth/login", s.handleLogin)
	authMux.HandleFunc("POST /api/auth/setup", s.handleSetup)
	authMux.HandleFunc("POST /api/auth/refresh", s.handleRefresh)
	authMux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	mux.Handle("/api/auth/", rl.Middleware(csrfMW(authMux)))

	// Deploy webhook — HMAC-authenticated by project secret, no admin JWT.
	mux.HandleFunc("POST /api/deploy/webhook", s.handleDeployWebhook)

	// Protected API endpoints
	api := http.NewServeMux()
	api.HandleFunc("GET /api/auth/me", s.handleMe)

	// Hosts
	api.HandleFunc("GET /api/hosts", s.handleListHosts)
	api.HandleFunc("POST /api/hosts", s.handleCreateHost)
	api.HandleFunc("GET /api/hosts/{id}", s.handleGetHost)
	api.HandleFunc("PUT /api/hosts/{id}", s.handleUpdateHost)
	api.HandleFunc("DELETE /api/hosts/{id}", s.handleDeleteHost)

	// Routes
	api.HandleFunc("GET /api/hosts/{id}/routes", s.handleListRoutes)
	api.HandleFunc("POST /api/hosts/{id}/routes", s.handleCreateRoute)
	api.HandleFunc("GET /api/routes/{id}", s.handleGetRoute)
	api.HandleFunc("PUT /api/routes/{id}", s.handleUpdateRoute)
	api.HandleFunc("DELETE /api/routes/{id}", s.handleDeleteRoute)

	// Logs — proxied to diaLOG via gRPC
	api.HandleFunc("GET /api/logs", s.handleSearchLogs)
	api.HandleFunc("GET /api/logs/stats", s.handleLogStats)
	api.HandleFunc("GET /api/logs/stream", s.handleStreamLogs)
	api.HandleFunc("GET /api/logs/{id}", s.handleGetLog)
	api.HandleFunc("PUT /api/logs/{id}/note", s.handleUpsertLogNote)
	api.HandleFunc("POST /api/logs/{id}/star", s.handleToggleLogStar)

	// Settings
	api.HandleFunc("GET /api/settings", s.handleGetSettings)
	api.HandleFunc("PUT /api/settings/{key}", s.handleUpdateSetting)

	// TLS
	api.HandleFunc("GET /api/tls/certificates", s.handleListCerts)
	api.HandleFunc("POST /api/tls/certificates", s.handleUploadCert)
	api.HandleFunc("DELETE /api/tls/certificates/{id}", s.handleDeleteCert)

	// System
	api.HandleFunc("GET /api/system/health", s.handleHealth)
	api.HandleFunc("GET /api/system/stats", s.handleSystemStats)
	api.HandleFunc("POST /api/system/reload", s.handleReload)
	api.HandleFunc("GET /api/system/health/backends", s.handleBackendHealth)

	// Audit log
	api.HandleFunc("GET /api/audit", s.handleListAudit)

	// WAF Rules — proxied to muWAF via gRPC
	api.HandleFunc("GET /api/waf/rules", s.handleListWafRules)
	api.HandleFunc("POST /api/waf/rules", s.handleCreateWafRule)
	api.HandleFunc("GET /api/waf/rules/{id}", s.handleGetWafRule)
	api.HandleFunc("PUT /api/waf/rules/{id}", s.handleUpdateWafRule)
	api.HandleFunc("DELETE /api/waf/rules/{id}", s.handleDeleteWafRule)
	api.HandleFunc("POST /api/waf/rules/import", s.handleImportWafRules)

	// WAF IP Management — proxied to muWAF via gRPC
	api.HandleFunc("GET /api/waf/ips", s.handleListWafIPs)
	api.HandleFunc("POST /api/waf/ips/ban", s.handleBanIP)
	api.HandleFunc("POST /api/waf/ips/unban", s.handleUnbanIP)
	api.HandleFunc("POST /api/waf/ips/whitelist", s.handleWhitelistIP)
	api.HandleFunc("DELETE /api/waf/ips/whitelist/{ip}", s.handleRemoveWhitelist)

	// WAF Exclusions — proxied to muWAF via gRPC
	api.HandleFunc("GET /api/waf/exclusions", s.handleListWafExclusions)
	api.HandleFunc("POST /api/waf/exclusions", s.handleCreateWafExclusion)
	api.HandleFunc("DELETE /api/waf/exclusions/{id}", s.handleDeleteWafExclusion)

	// WAF Events & Stats — proxied to muWAF via gRPC
	api.HandleFunc("GET /api/waf/events", s.handleSearchWafEvents)
	api.HandleFunc("GET /api/waf/stats", s.handleWafStats)

	// Agent management (admin JWT auth)
	api.HandleFunc("GET /api/agents", s.handleListAgents)
	api.HandleFunc("POST /api/agents", s.handleCreateAgent)
	api.HandleFunc("DELETE /api/agents/{id}", s.handleDeleteAgent)

	// Alerts (correlation engine output)
	api.HandleFunc("GET /api/alerts", s.handleListAlerts)
	api.HandleFunc("GET /api/alerts/stats", s.handleAlertStats)
	api.HandleFunc("GET /api/alerts/{id}", s.handleGetAlert)
	api.HandleFunc("POST /api/alerts/{id}/acknowledge", s.handleAckAlert)

	// Alerting channel tests (sends a synthetic alert via the real notifier)
	api.HandleFunc("POST /api/alerting/test/slack", s.handleTestSlackAlert)
	api.HandleFunc("POST /api/alerting/test/smtp", s.handleTestSMTPAlert)

	// Managed application deploys
	api.HandleFunc("GET /api/deploy/projects", s.handleListDeployProjects)
	api.HandleFunc("GET /api/deploy/projects/{slug}/secret", s.handleGetDeployProjectSecret)
	api.HandleFunc("PUT /api/deploy/projects/{slug}", s.handleUpdateDeployProject)
	api.HandleFunc("GET /api/deploy/deployments", s.handleListDeployments)
	api.HandleFunc("GET /api/deploy/deployments/{id}/events", s.handleListDeploymentEvents)
	api.HandleFunc("POST /api/deploy/deployments/{id}/rerun", s.handleRerunDeployment)
	api.HandleFunc("POST /api/deploy/projects/{slug}/deploy", s.handleManualDeploy)

	mux.Handle("/api/", s.authMiddleware(csrfMW(api)))

	// Agent API (X-Api-Key auth, no JWT)
	if s.agentSvc != nil {
		agentMux := http.NewServeMux()
		agentMux.HandleFunc("GET /api/v1/agent/config", s.agentSvc.HandleConfig)
		agentMux.HandleFunc("GET /api/v1/agent/watch", s.agentSvc.HandleWatch)
		mux.Handle("/api/v1/agent/", s.agentSvc.AuthMiddleware(agentMux))
	}

	// Health endpoint — JWT gerektirmez
	mux.HandleFunc("GET /health", s.handleHealth)

	// Frontend (embed.FS) — SPA fallback: dosya yoksa index.html dön
	if s.frontendFS != nil {
		fsHandler := http.FileServerFS(s.frontendFS)
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if _, err := fs.Stat(s.frontendFS, strings.TrimPrefix(r.URL.Path, "/")); err != nil {
				r2 := r.Clone(r.Context())
				r2.URL.Path = "/"
				fsHandler.ServeHTTP(w, r2)
				return
			}
			fsHandler.ServeHTTP(w, r)
		})
	}

	// Middleware zinciri
	var handler http.Handler = mux
	handler = corsMiddleware(handler)
	handler = middleware.SecurityHeaders(handler)
	handler = middleware.Recovery(handler)

	return handler
}

// --- System handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	if err := s.db.Health(r.Context()); err != nil {
		status = "degraded"
	}

	services := map[string]string{
		"database": status,
		"waf":      "unavailable",
		"logging":  "unavailable",
	}
	if s.wafClient != nil && s.wafClient.Healthy(r.Context()) {
		services["waf"] = "ok"
	}
	if s.logClient != nil {
		services["logging"] = "ok"
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":   status,
		"services": services,
	})
}

func (s *Server) handleSystemStats(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	stats := map[string]any{
		"uptime_seconds": int(time.Since(s.startTime).Seconds()),
		"goroutines":     runtime.NumGoroutine(),
		"memory": map[string]any{
			"alloc_mb":       m.Alloc / 1024 / 1024,
			"total_alloc_mb": m.TotalAlloc / 1024 / 1024,
			"sys_mb":         m.Sys / 1024 / 1024,
			"gc_cycles":      m.NumGC,
		},
		"go_version": runtime.Version(),
	}

	cfg := s.configHolder.Get()
	stats["config"] = map[string]any{
		"active_hosts": len(cfg.Hosts),
	}

	stats["services"] = map[string]any{
		"waf_connected": s.wafClient != nil,
		"log_connected": s.logClient != nil,
	}

	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if err := s.configHolder.Reload(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
}

func (s *Server) triggerReload() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.configHolder.Reload(ctx); err != nil {
		slog.Error("auto-reload failed", "error", err)
		return err
	}
	return nil
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func parseInt(s string) (int, error) {
	return strconv.Atoi(s)
}

func tlsX509KeyPair(certPEM, keyPEM []byte) (tls.Certificate, error) {
	return tls.X509KeyPair(certPEM, keyPEM)
}

func extractCertExpiry(certPEM []byte) time.Time {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Now().Add(365 * 24 * time.Hour)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Now().Add(365 * 24 * time.Hour)
	}
	return cert.NotAfter
}

func (s *Server) EnsureDefaultAdmin(ctx context.Context) error {
	exists, err := s.db.AdminExists(ctx)
	if err != nil {
		return fmt.Errorf("check admin: %w", err)
	}
	if exists {
		return nil
	}
	slog.Info("no admin user found — create one via POST /api/auth/setup")
	return nil
}

func (s *Server) auditLog(r *http.Request, action, targetType, targetID string, detail any) {
	user, _ := r.Context().Value(usernameKey).(string)
	if user == "" {
		user = "unknown"
	}
	ip := extractClientIP(r)
	s.db.WriteAuditLog(r.Context(), user, action, targetType, targetID, ip, detail)
}

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i != -1 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i != -1 {
		return ip[:i]
	}
	return ip
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	params := db.AuditSearchParams{
		Action: q.Get("action"),
	}
	if v := q.Get("from"); v != "" {
		params.From, _ = time.Parse(time.RFC3339, v)
	}
	if v := q.Get("to"); v != "" {
		params.To, _ = time.Parse(time.RFC3339, v)
	}
	if v := q.Get("limit"); v != "" {
		params.Limit, _ = strconv.Atoi(v)
	}
	if v := q.Get("offset"); v != "" {
		params.Offset, _ = strconv.Atoi(v)
	}

	entries, total, err := s.db.ListAuditLog(r.Context(), params)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if entries == nil {
		entries = []db.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data":   entries,
		"total":  total,
		"limit":  params.Limit,
		"offset": params.Offset,
	})
}

func (s *Server) handleBackendHealth(w http.ResponseWriter, r *http.Request) {
	if s.healthMgr != nil {
		writeJSON(w, http.StatusOK, s.healthMgr.GetAll())
		return
	}
	cfg := s.configHolder.Get()
	backends := make(map[string]string)
	for _, hc := range cfg.Hosts {
		for _, route := range hc.Routes {
			if route.Route.RouteType != "proxy" {
				continue
			}
			if route.Route.BackendURL != nil && *route.Route.BackendURL != "" {
				backends[*route.Route.BackendURL] = "unknown"
			}
			for _, u := range route.Route.BackendURLs {
				if u != "" {
					backends[u] = "unknown"
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, backends)
}

// requireWAF is a helper that returns true if the WAF client is available.
// If not, it writes a 503 response and returns false.
func (s *Server) requireWAF(w http.ResponseWriter) bool {
	if s.wafClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "muWAF service unavailable"})
		return false
	}
	return true
}

// requireLog is a helper that returns true if the log client is available.
// If not, it writes a 503 response and returns false.
func (s *Server) requireLog(w http.ResponseWriter) bool {
	if s.logClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "diaLOG service unavailable"})
		return false
	}
	return true
}
