package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"muvon/internal/config"
	"muvon/internal/health"
	logclient "muvon/internal/logger/grpcclient"
	"muvon/internal/proxy"
	"muvon/internal/router"
	tlspkg "muvon/internal/tls"
	wafclient "muvon/internal/waf/grpcclient"
)

func main() {
	var (
		centralURL = flag.String("central", envOr("AGENT_CENTRAL_URL", ""), "Central server URL (e.g. https://central.example.com:9443)")
		apiKey     = flag.String("api-key", envOr("AGENT_API_KEY", ""), "Agent API key from central")
		httpAddr   = flag.String("http", envOr("AGENT_HTTP_ADDR", ":80"), "HTTP listen address")
		httpsAddr  = flag.String("https", envOr("AGENT_HTTPS_ADDR", ":443"), "HTTPS listen address")
		logAddr    = flag.String("log-addr", envOr("AGENT_LOG_ADDR", ""), "Central diaLOG TCP address (host:port)")
		wafSocket  = flag.String("waf-socket", envOr("AGENT_WAF_SOCKET", "/tmp/muwaf.sock"), "Local muWAF Unix socket path")
		tlsCacheDir = flag.String("tls-cache", envOr("AGENT_TLS_CACHE", "/var/lib/agent/tls"), "Directory for ACME cert cache")
		logLevel   = flag.String("log-level", envOr("AGENT_LOG_LEVEL", "info"), "Log level")
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

	// TLS — ACME with local dir cache (no DB needed)
	tlsMgr := tlspkg.NewManagerNoDB(ch, *tlsCacheDir)

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
	if *logAddr != "" {
		logClient, err := logclient.DialTCP(*logAddr, *apiKey)
		if err != nil {
			slog.Warn("central diaLOG connection failed, running without logging", "error", err)
		} else {
			logSink = logClient
			slog.Info("connected to central diaLOG", "addr", *logAddr)
		}
	} else {
		slog.Warn("AGENT_LOG_ADDR not set, log ingestion disabled")
	}

	// Transport + Router
	transport := proxy.NewTransport()
	rt := router.New(ch, logSink, transport, hm, inspector, nil, "", nil)

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
