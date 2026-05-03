package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"muvon/internal/alerting"
	"muvon/internal/config"
	"muvon/internal/correlation"
	"muvon/internal/db"
	"muvon/internal/geoip"
	"muvon/internal/identity"
	"muvon/internal/logger"
	loggrpc "muvon/internal/logger/grpcserver"
	"muvon/internal/secret"
	pb "muvon/proto/logpb"
)

func main() {
	var (
		dsn        = flag.String("dsn", envOr("DIALOG_DSN", "postgres://dialog:dialog@localhost:5432/dialog?sslmode=disable"), "PostgreSQL connection string")
		socketPath = flag.String("socket", envOr("DIALOG_SOCKET", "/tmp/dialog.sock"), "Unix socket path for gRPC")
		tcpAddr    = flag.String("tcp-addr", envOr("DIALOG_TCP_ADDR", ""), "TCP listen address for agent log ingestion (e.g. :9001)")
		bufSize    = flag.Int("buffer", intEnvOr("DIALOG_BUFFER", 10000), "Log pipeline buffer size")
		workers    = flag.Int("workers", intEnvOr("DIALOG_WORKERS", 4), "Log pipeline worker count")
		batchSize  = flag.Int("batch", intEnvOr("DIALOG_BATCH", 1000), "Log pipeline batch size")
		flushMs    = flag.Int("flush-ms", intEnvOr("DIALOG_FLUSH_MS", 2000), "Log pipeline flush interval (ms)")
		// Container log pipeline — parallel to the http path; lower
		// defaults because container stdout volume is typically a
		// fraction of HTTP traffic (and we'd rather pay an extra worker
		// later than burn DB connections for nothing).
		cBufSize   = flag.Int("container-buffer", intEnvOr("DIALOG_CONTAINER_BUFFER", 10000), "Container log pipeline buffer size")
		cWorkers   = flag.Int("container-workers", intEnvOr("DIALOG_CONTAINER_WORKERS", 2), "Container log pipeline worker count")
		cBatch     = flag.Int("container-batch", intEnvOr("DIALOG_CONTAINER_BATCH", 1000), "Container log pipeline batch size")
		cFlushMs   = flag.Int("container-flush-ms", intEnvOr("DIALOG_CONTAINER_FLUSH_MS", 2000), "Container log pipeline flush interval (ms)")
		containerIngestEnabled = flag.Bool("container-ingest", boolEnvOr("DIALOG_CONTAINER_INGEST", true), "Enable container log ingest pipeline")
		logLevel      = flag.String("log-level", envOr("DIALOG_LOG_LEVEL", "info"), "Log level")
		encryptionKey = flag.String("encryption-key", envOr("MUVON_ENCRYPTION_KEY", ""), "AES-256-GCM encryption key for secrets in DB")
	)
	flag.Parse()
	setupLogger(*logLevel)

	slog.Info("diaLOG SIEM starting", "socket", *socketPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Database — dialog is the primary schema for reads/writes, but config
	// also pulls from the muvon schema (hosts, routes, deploy_*) so we add
	// it to search_path rather than qualifying every config query.
	database, err := db.New(ctx, *dsn, "dialog", "muvon")
	if err != nil {
		slog.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	if err := database.RunMigrations(ctx); err != nil {
		slog.Error("migrations failed", "error", err)
		os.Exit(1)
	}

	// Config holder — for alerting settings
	box := secret.NewBox(*encryptionKey)
	dbSrc := config.NewDBSource(database, box)
	ch := config.NewHolder(dbSrc, box)
	if err := ch.Init(ctx); err != nil {
		slog.Warn("config init failed, alerting may be unavailable", "error", err)
	}

	// Background config reload. Without this the snapshot loaded at
	// startup is frozen — admin-panel changes to JWT identity, GeoIP,
	// correlation thresholds, and alerting config never reach this
	// process. MUVON runs an equivalent loop in its own main; matching
	// the cadence here keeps the two services in sync within ~5s.
	go func() {
		ticker := time.NewTicker(5 * time.Second)
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

	// Log pipeline
	flushInterval := time.Duration(*flushMs) * time.Millisecond
	pipeline := logger.NewPipeline(database.Pool, *bufSize, *workers, *batchSize, flushInterval)

	// Container log pipeline — runs only when ingest is on. Producers
	// (deployer logship, agent dockerwatch) push batches via gRPC;
	// SendContainerLogBatch on the registered server fans them through
	// this pipeline to the container_logs hypertable.
	var containerPipeline *logger.ContainerPipeline
	if *containerIngestEnabled {
		containerFlushInterval := time.Duration(*cFlushMs) * time.Millisecond
		containerPipeline = logger.NewContainerPipeline(database.Pool, *cBufSize, *cWorkers, *cBatch, containerFlushInterval)
	} else {
		slog.Info("container log ingest disabled (DIALOG_CONTAINER_INGEST=false)")
	}

	// GeoIP — central enrichment for every log entry, regardless of whether
	// the entry came from the local Unix socket or an agent's TCP gRPC. The
	// Manager owns load state so a misconfigured path surfaces as a status
	// the admin UI can show instead of failing silently.
	geoMgr := geoip.NewManager()
	if cfg := ch.Get(); cfg.Global.GeoIPEnabled && cfg.Global.GeoIPDBPath != "" {
		if err := geoMgr.Apply(true, cfg.Global.GeoIPDBPath); err != nil {
			slog.Warn("GeoIP initial load failed; banner will display in admin UI", "error", err)
		}
	}
	ch.OnReload(func(newCfg *config.Config) {
		// Apply is idempotent: only reopens when (enabled, path) actually
		// changes, so the 5-second background reload does not thrash the
		// .mmdb file on every tick.
		_ = geoMgr.Apply(newCfg.Global.GeoIPEnabled, newCfg.Global.GeoIPDBPath)
	})
	pipeline.SetGeoEnricher(geoMgr.Lookup)

	// JWT identity enrichment — extracts claims from Authorization header
	// centrally. Host-scoped override wins when that host's override is
	// enabled; otherwise we fall back to the global config. This lets a
	// single MUVON front multiple tenant apps that sign with different
	// secrets.
	pipeline.SetIdentityHeaderResolver(func(host string) string {
		cfg := ch.Get()
		if hc, ok := cfg.Hosts[host]; ok && hc.IdentityHeaderName != "" {
			return hc.IdentityHeaderName
		}
		return "Authorization"
	})
	pipeline.SetRawTokenPolicy(func(host string) bool {
		cfg := ch.Get()
		hc, ok := cfg.Hosts[host]
		return ok && hc.StoreRawJWT
	})
	idExtractor := &identity.Extractor{}
	pipeline.SetIdentityEnricher(func(host, authHeader string) *logger.UserIdentity {
		cfg := ch.Get()
		if host != "" {
			if hc, ok := cfg.Hosts[host]; ok && hc.JWTIdentityEnabled {
				claims := hc.JWTClaims
				if len(claims) == 0 {
					claims = cfg.Global.JWTClaims
				}
				return idExtractor.ExtractFromBearer(authHeader, identity.Config{
					Enabled: true,
					Secret:  hc.JWTSecret,
					Claims:  claims,
				})
			}
		}
		return idExtractor.ExtractFromBearer(authHeader, identity.Config{
			Enabled: cfg.Global.JWTIdentityEnabled,
			Secret:  cfg.Global.JWTSecret,
			Claims:  cfg.Global.JWTClaims,
		})
	})

	// Alerting manager
	alertMgr := alerting.NewManager(database, func() alerting.Config {
		cfg := ch.Get()
		return alerting.Config{
			Enabled:         cfg.Global.AlertingEnabled,
			SlackWebhook:    cfg.Global.AlertingSlackWebhook,
			SMTPHost:        cfg.Global.AlertingSMTPHost,
			SMTPPort:        cfg.Global.AlertingSMTPPort,
			SMTPUsername:    cfg.Global.AlertingSMTPUsername,
			SMTPPassword:    cfg.Global.AlertingSMTPPassword,
			SMTPFrom:        cfg.Global.AlertingSMTPFrom,
			SMTPTo:          cfg.Global.AlertingSMTPTo,
			CooldownSeconds: cfg.Global.AlertingCooldownSeconds,
		}
	})
	alertMgr.AddNotifier(alerting.NewSlackNotifier(func() string {
		return ch.Get().Global.AlertingSlackWebhook
	}))
	alertMgr.AddNotifier(alerting.NewEmailNotifier(func() alerting.Config {
		cfg := ch.Get()
		return alerting.Config{
			SMTPHost:     cfg.Global.AlertingSMTPHost,
			SMTPPort:     cfg.Global.AlertingSMTPPort,
			SMTPUsername: cfg.Global.AlertingSMTPUsername,
			SMTPPassword: cfg.Global.AlertingSMTPPassword,
			SMTPFrom:     cfg.Global.AlertingSMTPFrom,
			SMTPTo:       cfg.Global.AlertingSMTPTo,
		}
	}))
	alertMgr.Start()

	// Correlation engine — subscribes to pipeline, produces alerts.
	// The config func is read on every event so admin-panel changes to
	// thresholds / paths take effect immediately after a config reload.
	corrEngine := correlation.New(alertMgr, func() config.CorrelationConfig {
		return ch.Get().Global.Correlation
	})
	corrEngine.Run(pipeline)

	// gRPC server on Unix socket
	os.Remove(*socketPath)
	lis, err := net.Listen("unix", *socketPath)
	if err != nil {
		slog.Error("unix socket listen failed", "error", err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer()
	// Pass the config holder's Get so read handlers (SearchLogs / GetLog /
	// GetLogStats) can resolve JWT display claim priority per-host from
	// live config, with the global list as fallback. No hard-coded claim
	// vocabulary in the server itself.
	logSrv := loggrpc.New(pipeline, database, ch.Get)
	if containerPipeline != nil {
		logSrv.SetContainerPipeline(containerPipeline)
	}
	logSrv.SetEnrichmentStatusFn(func() *pb.EnrichmentStatusResponse {
		gs := geoMgr.GetStatus()
		resp := &pb.EnrichmentStatusResponse{
			GeoipState: gs.State,
			GeoipPath:  gs.Path,
			GeoipError: gs.Error,
		}
		if !gs.LoadedAt.IsZero() {
			resp.GeoipLoadedAt = gs.LoadedAt.UTC().Format(time.RFC3339)
		}
		cfg := ch.Get()
		if cfg.Global.JWTIdentityEnabled || hasHostJWTOverride(cfg) {
			resp.JwtIdentityState = "ok"
		} else {
			resp.JwtIdentityState = "disabled"
		}
		resp.JwtIdentityHostOverrides = int32(countHostJWTOverrides(cfg))
		return resp
	})
	pb.RegisterLogServiceServer(grpcServer, logSrv)

	// TCP gRPC server — for agents sending logs over the network
	var tcpServer *grpc.Server

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig)
		grpcServer.GracefulStop()
		if tcpServer != nil {
			tcpServer.GracefulStop()
		}
		corrEngine.Stop()
		pipeline.Stop()
		if containerPipeline != nil {
			containerPipeline.Stop()
		}
		alertMgr.Stop()
		_ = geoMgr.Close()
		cancel()
	}()
	if *tcpAddr != "" {
		tcpLis, err := net.Listen("tcp", *tcpAddr)
		if err != nil {
			slog.Error("tcp listen failed", "addr", *tcpAddr, "error", err)
			os.Exit(1)
		}
		tcpServer = grpc.NewServer(
			grpc.UnaryInterceptor(agentKeyUnaryInterceptor(database)),
			grpc.StreamInterceptor(agentKeyStreamInterceptor(database)),
		)
		pb.RegisterLogServiceServer(tcpServer, logSrv)
		go func() {
			slog.Info("diaLOG TCP gRPC listening", "addr", *tcpAddr)
			if err := tcpServer.Serve(tcpLis); err != nil {
				slog.Error("TCP gRPC server error", "error", err)
			}
		}()
	}

	slog.Info("diaLOG gRPC server listening", "socket", *socketPath)
	if err := grpcServer.Serve(lis); err != nil {
		slog.Error("gRPC server error", "error", err)
		os.Exit(1)
	}

	slog.Info("diaLOG shutdown complete")
}

func agentKeyUnaryInterceptor(database *db.DB) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if err := validateAgentKey(ctx, database); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func agentKeyStreamInterceptor(database *db.DB) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := validateAgentKey(ss.Context(), database); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

func validateAgentKey(ctx context.Context, database *db.DB) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}
	keys := md.Get("x-api-key")
	if len(keys) == 0 {
		return status.Error(codes.Unauthenticated, "missing x-api-key")
	}
	valid, err := database.ValidateAgentKey(ctx, keys[0])
	if err != nil || !valid {
		return status.Error(codes.Unauthenticated, "invalid api key")
	}
	return nil
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

// hasHostJWTOverride returns true when at least one host has its own JWT
// identity config turned on. The overall enrichment state is still "ok" in
// that case even when the global toggle is off, because the SIEM will pick
// up identities for those hosts.
func hasHostJWTOverride(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, hc := range cfg.Hosts {
		if hc.JWTIdentityEnabled {
			return true
		}
	}
	return false
}

func countHostJWTOverrides(cfg *config.Config) int {
	if cfg == nil {
		return 0
	}
	n := 0
	for _, hc := range cfg.Hosts {
		if hc.JWTIdentityEnabled {
			n++
		}
	}
	return n
}

func intEnvOr(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return fallback
}

func boolEnvOr(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "TRUE", "True", "yes", "YES":
		return true
	case "0", "false", "FALSE", "False", "no", "NO":
		return false
	}
	return fallback
}
