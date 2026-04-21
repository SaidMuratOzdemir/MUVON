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

	"sync/atomic"

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
		logLevel      = flag.String("log-level", envOr("DIALOG_LOG_LEVEL", "info"), "Log level")
		encryptionKey = flag.String("encryption-key", envOr("MUVON_ENCRYPTION_KEY", ""), "AES-256-GCM encryption key for secrets in DB")
	)
	flag.Parse()
	setupLogger(*logLevel)

	slog.Info("diaLOG SIEM starting", "socket", *socketPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Database
	database, err := db.New(ctx, *dsn, "dialog")
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

	// Log pipeline
	flushInterval := time.Duration(*flushMs) * time.Millisecond
	pipeline := logger.NewPipeline(database.Pool, *bufSize, *workers, *batchSize, flushInterval)

	// GeoIP — load if configured; enriches all incoming log entries centrally
	var geoPtr atomic.Pointer[geoip.Reader]
	if cfg := ch.Get(); cfg.Global.GeoIPEnabled && cfg.Global.GeoIPDBPath != "" {
		if gr, err := geoip.Open(cfg.Global.GeoIPDBPath); err != nil {
			slog.Warn("GeoIP load failed", "path", cfg.Global.GeoIPDBPath, "error", err)
		} else {
			geoPtr.Store(gr)
			slog.Info("GeoIP database loaded", "path", cfg.Global.GeoIPDBPath)
		}
	}
	ch.OnReload(func(newCfg *config.Config) {
		if !newCfg.Global.GeoIPEnabled || newCfg.Global.GeoIPDBPath == "" {
			return
		}
		if cur := geoPtr.Load(); cur == nil {
			if gr, err := geoip.Open(newCfg.Global.GeoIPDBPath); err == nil {
				geoPtr.Store(gr)
			}
		} else {
			cur.Reload(newCfg.Global.GeoIPDBPath)
		}
	})
	pipeline.SetGeoEnricher(func(ip string) (string, string) {
		if gr := geoPtr.Load(); gr != nil {
			return gr.Lookup(ip)
		}
		return "", ""
	})

	// JWT identity enrichment — extracts claims from Authorization header centrally
	idExtractor := &identity.Extractor{}
	pipeline.SetIdentityEnricher(func(authHeader string) *logger.UserIdentity {
		cfg := ch.Get()
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
	logSrv := loggrpc.New(pipeline, database)
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
		alertMgr.Stop()
		if gr := geoPtr.Load(); gr != nil {
			gr.Close()
		}
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

func intEnvOr(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return fallback
}
