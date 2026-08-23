package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	dialog "muvon"
	"muvon/internal/admin"
	"muvon/internal/agentctrl"
	"muvon/internal/agentsvc"
	"muvon/internal/config"
	"muvon/internal/db"
	deployerclient "muvon/internal/deployer/grpcclient"
	"muvon/internal/health"
	logclient "muvon/internal/logger/grpcclient"
	"muvon/internal/proxy"
	"muvon/internal/router"
	"muvon/internal/scheduler"
	"muvon/internal/secret"
	tlspkg "muvon/internal/tls"
	"muvon/internal/version"
	"fmt"

	// Embed the IANA timezone database so the scheduler can LoadLocation
	// arbitrary timezones in the CGO_ENABLED=0 static binary, where host
	// tzdata may be absent (scratch/distroless images).
	_ "time/tzdata"
)

// minJWTSecretLen matches what install.sh generates (openssl rand -hex 32)
// and what .env.example asks for.
const minJWTSecretLen = 32

func main() {
	var (
		dsn                  = flag.String("dsn", envOr("MUVON_DSN", "postgres://dialog:dialog@localhost:5432/dialog?sslmode=disable"), "PostgreSQL connection string")
		httpAddr             = flag.String("http", envOr("MUVON_HTTP_ADDR", ":80"), "HTTP listen address")
		httpsAddr            = flag.String("https", envOr("MUVON_HTTPS_ADDR", ":443"), "HTTPS listen address")
		adminAddr            = flag.String("admin", envOr("MUVON_ADMIN_ADDR", ":9443"), "Admin API listen address. Always started, plain HTTP; restrict it at the network layer (compose publishes it on 127.0.0.1 only)")
		adminDomain          = flag.String("admin-domain", envOr("MUVON_ADMIN_DOMAIN", ""), "Additionally serve the admin panel on this domain via :443 (e.g. muvon.example.com)")
		jwtSecret            = flag.String("jwt-secret", envOr("MUVON_JWT_SECRET", ""), "JWT signing secret for admin sessions; required, at least 32 characters")
		logSocket            = flag.String("log-socket", envOr("MUVON_LOG_SOCKET", "/tmp/dialog.sock"), "diaLOG Unix socket path")
		deployerSocket       = flag.String("deployer-socket", envOr("MUVON_DEPLOYER_SOCKET", "/run/muvon/deployer.sock"), "muvon-deployer Unix socket path (live container introspection + log tail)")
		logLevel             = flag.String("log-level", envOr("MUVON_LOG_LEVEL", "info"), "Log level")
		encryptionKey        = flag.String("encryption-key", envOr("MUVON_ENCRYPTION_KEY", ""), "AES-256-GCM encryption key for secrets in DB")
		// publicIP is what central reports as its own externally-reachable
		// IP for DNS verification. Auto-detected on startup if empty;
		// operator can pin via MUVON_PUBLIC_IP when ifconfig.me is unwanted
		// (air-gapped install, behind GeoDNS, etc).
		publicIPFlag         = flag.String("public-ip", envOr("MUVON_PUBLIC_IP", ""), "Central's externally-reachable IP (auto-detected via ifconfig.me when empty)")
		configReloadInterval = flag.Duration("config-reload-interval", envDuration("MUVON_CONFIG_RELOAD_INTERVAL", 5*time.Second), "Background config reload interval")
		showVersion          = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()
	if *showVersion {
		fmt.Println("muvon " + version.String())
		return
	}
	setupLogger(*logLevel)

	// An admin session is a signed cookie, so a guessable signing secret is a
	// login bypass. There is no default to fall back to: 32 characters is what
	// the installer generates and what the sample env documents.
	if len(*jwtSecret) < minJWTSecretLen {
		slog.Error("MUVON_JWT_SECRET is required and must be at least 32 characters",
			"have_length", len(*jwtSecret),
			"generate_with", "openssl rand -hex 32")
		os.Exit(1)
	}

	slog.Info("MUVON starting",
		"version", version.String(),
		"http", *httpAddr,
		"https", *httpsAddr,
		"admin_domain", *adminDomain,
		"log_socket", *logSocket,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Keep the Cloudflare edge range set fresh so client-IP resolution stays
	// correct if the operator flips a zone's proxy (orange cloud) on/off.
	proxy.StartCloudflareSync(ctx, nil)
	// Cloudflare client-IP trust is OPT-IN via a shared secret the operator
	// injects with a CF Transform Rule (CF egress IPs are shared across all
	// accounts, so peer-in-range alone is spoofable). Empty = disabled.
	proxy.SetCloudflareTrust(os.Getenv("MUVON_CLOUDFLARE_IP_HEADER"), os.Getenv("MUVON_CLOUDFLARE_IP_SECRET"))

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
	box, err := secret.NewBox(*encryptionKey)
	if err != nil {
		slog.Error("MUVON_ENCRYPTION_KEY is required: it encrypts secret settings and component env values, and seeds the agent command signing key", "error", err)
		os.Exit(1)
	}
	dbSrc := config.NewDBSource(database, box)
	ch := config.NewHolder(dbSrc, box)
	if err := ch.Init(ctx); err != nil {
		slog.Error("config init failed", "error", err)
		os.Exit(1)
	}

	// Agent service — serves config to remote agents via SSE + carries
	// the central → agent command channel.
	agentBroadcaster := agentsvc.NewBroadcaster()
	agentSvc := agentsvc.NewService(database, ch, agentBroadcaster)
	// HMAC key for the agent command channel, derived from the same
	// encryption key the secret box uses.
	signingKey, err := agentctrl.DeriveSigningKey(*encryptionKey)
	if err != nil {
		slog.Error("agent command signing key derivation failed", "error", err)
		os.Exit(1)
	}
	agentSvc.SetCommandSigningKey(signingKey)
	// Whenever config reloads, push to all connected agents
	ch.OnReload(func(_ *config.Config) {
		agentBroadcaster.Broadcast()
	})

	// Sweeper — every 30s, expire stale agent_commands rows so the
	// admin UI's "stuck commands" view stays honest.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := database.ResetStaleAgentCommands(ctx); err != nil {
					slog.Warn("agent command sweeper failed", "error", err)
				} else if n > 0 {
					slog.Info("agent commands expired", "count", n)
				}
			}
		}
	}()

	// Scheduler — central-only goroutine that turns due scheduled_jobs into
	// pending scheduled_job_runs. The deployer (central muvon-deployer or an
	// edge agent) is the executor; this side only enqueues + advances cron.
	sched := scheduler.New(database, 30*time.Second)
	go func() {
		if err := sched.Run(ctx); err != nil && ctx.Err() == nil {
			slog.Error("scheduler stopped", "error", err)
		}
	}()

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
	// Same fail-open shape as diaLOG: if the socket is missing the admin
	// handlers return 503 and the UI shows a degraded banner, but the
	// proxy keeps serving traffic.
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

	// Detect central's own public IP for DNS-target hints. Best-effort:
	// failure leaves it empty and the admin UI falls back to agent IPs.
	centralPublicIP := strings.TrimSpace(*publicIPFlag)
	if centralPublicIP == "" {
		centralPublicIP = detectPublicIP(ctx)
	}
	if centralPublicIP != "" {
		slog.Info("central public IP", "ip", centralPublicIP)
	}

	// Admin server — central admin gateway
	adminSrv := admin.NewServer(database, *jwtSecret, ch, logClient, deployerClient, tlsMgr, hm, agentSvc, frontendFS, centralPublicIP, *encryptionKey)
	if err := adminSrv.EnsureDefaultAdmin(ctx); err != nil {
		slog.Warn("admin check failed", "error", err)
	}
	// Prune refresh tokens whose absolute expiry has passed. Hourly is a fine
	// cadence — the rows are tiny and hanging around for an extra hour does
	// not weaken the security model (they are already marked expired).
	adminSrv.StartRefreshTokenCleanup(ctx, time.Hour)

	// Router — main reverse proxy handler
	// If adminDomain is set, the admin panel is also served on :443 for that
	// domain. The :9443 listener still runs: the upgrade flow polls it locally.
	// Central terminates only hosts bound with target_kind="central" — the
	// proxy returns 421 for anything else so misdirected traffic is loud.
	rt := router.New(ch, logSink, transport, hm, database, frontendFS, *adminDomain, adminSrv.Handler(), "central", "")

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

// detectPublicIP asks ifconfig.me for our IPv4 address. Short timeout so
// startup isn't blocked when the host is offline or the service is down;
// empty return signals "skip" to the caller. Tied to MUVON_PUBLIC_IP env
// — operators in air-gapped environments pin the value explicitly.
func detectPublicIP(ctx context.Context) string {
	c := &http.Client{Timeout: 5 * time.Second}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, "https://ifconfig.me", nil)
	if err != nil {
		return ""
	}
	resp, err := c.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}
