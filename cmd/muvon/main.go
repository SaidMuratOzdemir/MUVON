package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	dialog "muvon"
	"muvon/internal/admin"
	"muvon/internal/agentsvc"
	"muvon/internal/config"
	"muvon/internal/db"
	deployerclient "muvon/internal/deployer/grpcclient"
	"muvon/internal/health"
	logclient "muvon/internal/logger/grpcclient"
	"muvon/internal/proxy"
	"muvon/internal/router"
	"muvon/internal/secret"
	tlspkg "muvon/internal/tls"
	wafclient "muvon/internal/waf/grpcclient"
)

func main() {
	var (
		dsn                  = flag.String("dsn", envOr("MUVON_DSN", "postgres://dialog:dialog@localhost:5432/dialog?sslmode=disable"), "PostgreSQL connection string")
		httpAddr             = flag.String("http", envOr("MUVON_HTTP_ADDR", ":80"), "HTTP listen address")
		httpsAddr            = flag.String("https", envOr("MUVON_HTTPS_ADDR", ":443"), "HTTPS listen address")
		adminAddr            = flag.String("admin", envOr("MUVON_ADMIN_ADDR", ":9443"), "Admin API listen address (used only when admin-domain is not set)")
		adminDomain          = flag.String("admin-domain", envOr("MUVON_ADMIN_DOMAIN", ""), "Serve admin panel on this domain via :443 (e.g. muvon.example.com). When set, :9443 is not started.")
		jwtSecret            = flag.String("jwt-secret", envOr("MUVON_JWT_SECRET", "change-me-in-production"), "JWT signing secret")
		wafSocket            = flag.String("waf-socket", envOr("MUVON_WAF_SOCKET", "/tmp/muwaf.sock"), "muWAF Unix socket path")
		logSocket            = flag.String("log-socket", envOr("MUVON_LOG_SOCKET", "/tmp/dialog.sock"), "diaLOG Unix socket path")
		deployerSocket       = flag.String("deployer-socket", envOr("MUVON_DEPLOYER_SOCKET", "/run/muvon/deployer.sock"), "muvon-deployer Unix socket path (live container introspection + log tail)")
		logLevel             = flag.String("log-level", envOr("MUVON_LOG_LEVEL", "info"), "Log level")
		encryptionKey        = flag.String("encryption-key", envOr("MUVON_ENCRYPTION_KEY", ""), "AES-256-GCM encryption key for secrets in DB")
		configReloadInterval = flag.Duration("config-reload-interval", envDuration("MUVON_CONFIG_RELOAD_INTERVAL", 5*time.Second), "Background config reload interval")
	)
	flag.Parse()
	setupLogger(*logLevel)

	slog.Info("MUVON starting",
		"http", *httpAddr,
		"https", *httpsAddr,
		"admin_domain", *adminDomain,
		"waf_socket", *wafSocket,
		"log_socket", *logSocket,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Database — MUVON only needs hosts, routes, settings, TLS, admin_users tables
	database, err := db.New(ctx, *dsn, "muvon")
	if err != nil {
		slog.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	if err := database.RunMigrations(ctx); err != nil {
		slog.Error("migrations failed", "error", err)
		os.Exit(1)
	}

	// Config
	box := secret.NewBox(*encryptionKey)
	dbSrc := config.NewDBSource(database, box)
	ch := config.NewHolder(dbSrc, box)
	if err := ch.Init(ctx); err != nil {
		slog.Error("config init failed", "error", err)
		os.Exit(1)
	}

	// Agent service — serves config to remote agents via SSE
	agentBroadcaster := agentsvc.NewBroadcaster()
	agentSvc := agentsvc.NewService(database, ch, agentBroadcaster)
	// Whenever config reloads, push to all connected agents
	ch.OnReload(func(_ *config.Config) {
		agentBroadcaster.Broadcast()
	})

	// TLS
	tlsMgr := tlspkg.NewManager(database, ch, *adminDomain)
	// Hand the TLS manager to the agent service so an agent-uploaded cert
	// invalidates central's in-memory cache straight away. Admin-uploaded
	// certs already invalidate via the cert handlers; this closes the loop
	// for the reverse direction.
	agentSvc.SetTLSManager(tlsMgr)

	// Health manager
	hm := health.NewManager()
	for _, hc := range ch.Get().Hosts {
		for _, r := range hc.Routes {
			if r.Route.BackendURL != nil {
				hm.Register(*r.Route.BackendURL)
			}
			for _, u := range r.Route.BackendURLs {
				hm.Register(u)
			}
			for _, b := range r.ManagedBackends {
				hm.RegisterWithHealth(b.BackendURL, b.HealthURL)
			}
		}
	}
	hm.Start()

	// OnReload callbacks — keep caches and health checks in sync
	ch.OnReload(func(newCfg *config.Config) {
		// Clear stale per-route rate limiters
		proxy.ClearRouteLimiters()

		// Invalidate TLS cache for hosts that no longer exist
		tlsMgr.InvalidateMissing(newCfg)

		// Re-register backends for health checking
		hm.SyncBackends(newCfg)
	})
	if *configReloadInterval > 0 {
		go func() {
			ticker := time.NewTicker(*configReloadInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := ch.Reload(ctx); err != nil {
						slog.Warn("background config reload failed", "error", err)
					}
				}
			}
		}()
	}

	// WAF client — connect to muWAF, graceful degradation if unavailable
	var inspector proxy.Inspector
	var wafInspector *wafclient.RemoteInspector
	wafInspector, err = wafclient.Dial(*wafSocket)
	if err != nil {
		slog.Warn("muWAF connection failed, running without WAF", "error", err)
		wafInspector = nil
	} else {
		inspector = wafInspector
		slog.Info("connected to muWAF", "socket", *wafSocket)
	}

	// Log client — connect to diaLOG SIEM, graceful degradation if unavailable
	var logSink proxy.LogSink
	var logClient *logclient.RemoteLogSink
	logClient, err = logclient.Dial(*logSocket)
	if err != nil {
		slog.Warn("diaLOG connection failed, running without logging", "error", err)
		logClient = nil
	} else {
		logSink = logClient
		slog.Info("connected to diaLOG", "socket", *logSocket)
	}

	// Deployer client — live container introspection + log tail bridge.
	// Same fail-open shape as muWAF / diaLOG: if the socket is missing
	// the admin handlers return 503 and the UI shows a degraded banner,
	// but the proxy keeps serving traffic.
	var deployerClient *deployerclient.RemoteDeployer
	if dc, err := deployerclient.Dial(*deployerSocket); err != nil {
		slog.Warn("muvon-deployer connection failed, running without live container tail", "error", err)
	} else {
		deployerClient = dc
		slog.Info("connected to muvon-deployer", "socket", *deployerSocket)
	}

	// Frontend FS
	frontendFS, err := fs.Sub(dialog.FrontendFS, "frontend/dist")
	if err != nil {
		slog.Error("frontend FS failed", "error", err)
		os.Exit(1)
	}

	// Transport
	transport := proxy.NewTransport()

	// Admin server — central admin gateway
	adminSrv := admin.NewServer(database, *jwtSecret, ch, wafInspector, logClient, deployerClient, tlsMgr, hm, agentSvc, frontendFS)
	if err := adminSrv.EnsureDefaultAdmin(ctx); err != nil {
		slog.Warn("admin check failed", "error", err)
	}
	// Prune refresh tokens whose absolute expiry has passed. Hourly is a fine
	// cadence — the rows are tiny and hanging around for an extra hour does
	// not weaken the security model (they are already marked expired).
	adminSrv.StartRefreshTokenCleanup(ctx, time.Hour)

	// Router — main reverse proxy handler
	// If adminDomain is set, admin panel is served on :443 for that domain; :9443 is not started.
	rt := router.New(ch, logSink, transport, hm, inspector, database, frontendFS, *adminDomain, adminSrv.Handler())

	connStateFn := func(_ net.Conn, state http.ConnState) {
		_ = state
	}

	// HTTP server (:80) — ACME + redirect
	httpServer := &http.Server{
		Addr:              *httpAddr,
		Handler:           tlsMgr.HTTPHandler(router.ForceHTTPSHandler(ch, *adminDomain)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 13,
		ConnState:         connStateFn,
	}

	// HTTPS server (:443) — main reverse proxy
	httpsServer := &http.Server{
		Addr:              *httpsAddr,
		Handler:           rt.Handler(),
		TLSConfig:         tlsMgr.TLSConfig(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 13,
		ConnState:         connStateFn,
	}

	// Admin server (:9443) always listens on all interfaces inside the process.
	// Access control is enforced at the network layer:
	//   - In Docker: docker-compose maps "127.0.0.1:9443:9443" — host-loopback only.
	//   - Bare-metal without adminDomain: use -admin flag or firewall to restrict.
	localAdminAddr := *adminAddr
	adminServer := &http.Server{
		Addr:              localAdminAddr,
		Handler:           adminSrv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 13,
	}

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig)
		cancel()

		shutCtx, shutCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutCancel()
		httpServer.Shutdown(shutCtx)
		httpsServer.Shutdown(shutCtx)
		adminServer.Shutdown(shutCtx)

		hm.Stop()
		if wafInspector != nil {
			wafInspector.Close()
		}
		if logClient != nil {
			logClient.Close()
		}
		if deployerClient != nil {
			deployerClient.Close()
		}
		database.Close()
		os.Exit(0)
	}()

	// Start servers
	errc := make(chan error, 3)

	go func() {
		slog.Info("HTTP server starting", "addr", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			errc <- err
		}
	}()

	go func() {
		slog.Info("HTTPS server starting", "addr", httpsServer.Addr)
		ln, err := tls.Listen("tcp", httpsServer.Addr, httpsServer.TLSConfig)
		if err != nil {
			errc <- err
			return
		}
		if err := httpsServer.Serve(ln); err != http.ErrServerClosed {
			errc <- err
		}
	}()

	go func() {
		slog.Info("Admin server starting", "addr", adminServer.Addr)
		if err := adminServer.ListenAndServe(); err != http.ErrServerClosed {
			errc <- err
		}
	}()
	if *adminDomain != "" {
		slog.Info("Admin panel served on :443", "domain", *adminDomain)
	}

	if err := <-errc; err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

func setupLogger(level string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(handler))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	if seconds, err := strconv.Atoi(v); err == nil {
		return time.Duration(seconds) * time.Second
	}
	return fallback
}
