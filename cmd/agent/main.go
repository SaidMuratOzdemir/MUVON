package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"muvon/internal/config"
	"muvon/internal/deployer"
	"muvon/internal/deployer/logship"
	"muvon/internal/health"
	logclient "muvon/internal/logger/grpcclient"
	"muvon/internal/proxy"
	"muvon/internal/router"
	tlspkg "muvon/internal/tls"
	wafclient "muvon/internal/waf/grpcclient"
)

func main() {
	var (
		centralURL  = flag.String("central", envOr("AGENT_CENTRAL_URL", ""), "Central server URL (e.g. https://central.example.com:9443)")
		apiKey      = flag.String("api-key", envOr("AGENT_API_KEY", ""), "Agent API key from central")
		httpAddr    = flag.String("http", envOr("AGENT_HTTP_ADDR", ":80"), "HTTP listen address")
		httpsAddr   = flag.String("https", envOr("AGENT_HTTPS_ADDR", ":443"), "HTTPS listen address")
		logAddr     = flag.String("log-addr", envOr("AGENT_LOG_ADDR", ""), "Central diaLOG TCP address (host:port)")
		wafSocket   = flag.String("waf-socket", envOr("AGENT_WAF_SOCKET", "/tmp/muwaf.sock"), "Local muWAF Unix socket path")
		tlsCacheDir = flag.String("tls-cache", envOr("AGENT_TLS_CACHE", "/var/lib/agent/tls"), "Directory for ACME cert cache")
		logLevel    = flag.String("log-level", envOr("AGENT_LOG_LEVEL", "info"), "Log level")
		// Container log shipping (dockerwatch) — when AGENT_DOCKER_SOCKET
		// is reachable, ships every container's stdout/stderr to central
		// dialog-siem over the same TCP gRPC channel that already carries
		// HTTP logs. host_id distinguishes agent hosts from central in
		// the SIEM. Silently disabled when the socket is unreadable.
		dockerSocket    = flag.String("docker-socket", envOr("AGENT_DOCKER_SOCKET", "unix:///var/run/docker.sock"), "Local Docker daemon socket for container log capture (empty/unreadable = disabled)")
		dockerwatch     = flag.Bool("dockerwatch", boolEnvOr("AGENT_DOCKERWATCH_ENABLED", true), "Enable container log shipping to central dialog-siem")
		dwHostID        = flag.String("dockerwatch-host-id", envOr("AGENT_HOST_ID", ""), "Identifier for this agent host in shipped logs (default: hostname)")
		dwSpoolDir      = flag.String("dockerwatch-spool-dir", envOr("AGENT_DOCKERWATCH_SPOOL_DIR", "/var/lib/agent/logship"), "Local on-disk spool for container log batches when central is unreachable")
		dwSpoolMaxBytes = flag.Int64("dockerwatch-spool-max-bytes", int64EnvOr("AGENT_DOCKERWATCH_SPOOL_MAX_BYTES", 256*1024*1024), "Total spool disk budget in bytes")
		dwBatchSize     = flag.Int("dockerwatch-batch", intEnvOr("AGENT_DOCKERWATCH_BATCH", 500), "Lines per shipping batch")
		dwFlushMs       = flag.Int("dockerwatch-flush-ms", intEnvOr("AGENT_DOCKERWATCH_FLUSH_MS", 1000), "Time between forced flushes (ms)")
		dwMaxLine       = flag.Int("dockerwatch-max-line", intEnvOr("AGENT_DOCKERWATCH_MAX_LINE", 16384), "Per-line truncation threshold")
		dwManagedOnly   = flag.Bool("dockerwatch-managed-only", boolEnvOr("AGENT_DOCKERWATCH_MANAGED_ONLY", false), "Tail only containers labelled muvon.managed=true (default false on agent — operators rarely paint that label themselves)")
	)
	flag.Parse()
	setupLogger(*logLevel)

	if *centralURL == "" || *apiKey == "" {
		slog.Error("AGENT_CENTRAL_URL and AGENT_API_KEY are required")
		os.Exit(1)
	}

	slog.Info("AGENT starting",
		"central", *centralURL,
		"http", *httpAddr,
		"https", *httpsAddr,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Config source — pulls from central server
	src := config.NewAgentSource(*centralURL, *apiKey)
	ch := config.NewHolder(src, nil)
	if err := ch.Init(ctx); err != nil {
		slog.Error("initial config load from central failed", "error", err)
		os.Exit(1)
	}

	// TLS — ACME with local dir cache + central cert sync. The sync layer
	// makes admin-uploaded certs win over autocert (pull) and stores
	// freshly-issued ACME certs back on central as a backup (push).
	certSync := tlspkg.NewAgentCertSync(*centralURL, *apiKey)
	tlsMgr := tlspkg.NewManagerNoDB(ch, *tlsCacheDir, certSync)

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
		}
	}
	hm.Start()

	// OnReload callbacks
	ch.OnReload(func(newCfg *config.Config) {
		proxy.ClearRouteLimiters()
		tlsMgr.InvalidateMissing(newCfg)
		hm.SyncBackends(newCfg)
	})

	// WAF client — connect to local muWAF if available (optional)
	var inspector proxy.Inspector
	wafInspector, err := wafclient.Dial(*wafSocket)
	if err != nil {
		slog.Warn("muWAF not available, running without WAF", "error", err)
	} else {
		inspector = wafInspector
		slog.Info("connected to local muWAF", "socket", *wafSocket)
	}

	// Log client — send logs to central diaLOG over TCP
	var logSink proxy.LogSink
	var logClient *logclient.RemoteLogSink
	if *logAddr != "" {
		var err error
		logClient, err = logclient.DialTCP(*logAddr, *apiKey)
		if err != nil {
			slog.Warn("central diaLOG connection failed, running without logging", "error", err)
		} else {
			logSink = logClient
			slog.Info("connected to central diaLOG", "addr", *logAddr)
		}
	} else {
		slog.Warn("AGENT_LOG_ADDR not set, log ingestion disabled")
	}

	// Container log shipping — reuses the central diaLOG TCP connection
	// and the same x-api-key auth. host_id defaults to os.Hostname so
	// the SIEM groups logs per agent without any extra config.
	if *dockerwatch && logClient != nil && *dockerSocket != "" {
		hostID := strings.TrimSpace(*dwHostID)
		if hostID == "" {
			if h, err := os.Hostname(); err == nil && h != "" {
				hostID = "agent:" + h
			} else {
				hostID = "agent"
			}
		}
		if dockerCli, err := deployer.NewDockerClient(*dockerSocket); err != nil {
			slog.Info("dockerwatch: docker socket unreachable; container log shipping disabled",
				"socket", *dockerSocket, "error", err)
		} else if spool, err := logship.NewSpool(*dwSpoolDir, *dwSpoolMaxBytes, *dwSpoolMaxBytes/16); err != nil {
			slog.Warn("dockerwatch: spool init failed; container log shipping disabled",
				"dir", *dwSpoolDir, "error", err)
		} else {
			mgr := logship.New(dockerCli, logClient, spool, logship.Options{
				HostID:      hostID,
				MaxLine:     *dwMaxLine,
				BatchSize:   *dwBatchSize,
				Flush:       time.Duration(*dwFlushMs) * time.Millisecond,
				ManagedOnly: *dwManagedOnly,
			})
			go mgr.Run(ctx)
			slog.Info("dockerwatch: started",
				"host_id", hostID,
				"docker_socket", *dockerSocket,
				"spool_dir", *dwSpoolDir,
				"managed_only", *dwManagedOnly)
		}
	} else if !*dockerwatch {
		slog.Info("dockerwatch: disabled (AGENT_DOCKERWATCH_ENABLED=false)")
	} else if logClient == nil {
		slog.Info("dockerwatch: skipped (no central diaLOG connection)")
	}

	// Transport + Router
	transport := proxy.NewTransport()
	rt := router.New(ch, logSink, transport, hm, inspector, nil, nil, "", nil)

	// HTTP server — ACME + redirect
	httpServer := &http.Server{
		Addr:              *httpAddr,
		Handler:           tlsMgr.HTTPHandler(router.ForceHTTPSHandler(ch, "")),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 13,
	}

	// HTTPS server — main reverse proxy
	httpsServer := &http.Server{
		Addr:              *httpsAddr,
		Handler:           rt.Handler(),
		TLSConfig:         tlsMgr.TLSConfig(),
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

		hm.Stop()
		if wafInspector != nil {
			wafInspector.Close()
		}
		os.Exit(0)
	}()

	// Config watcher — SSE push from central (hot reload)
	go src.Watch(ctx, func() {
		if err := ch.Reload(ctx); err != nil {
			slog.Error("config reload failed", "error", err)
		}
	})

	// Start servers
	errc := make(chan error, 2)

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
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func intEnvOr(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return def
}

func int64EnvOr(key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return n
	}
	return def
}

func boolEnvOr(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes":
		return true
	case "0", "false", "no":
		return false
	}
	return def
}
