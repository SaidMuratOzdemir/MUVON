package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"muvon/internal/config"
	"muvon/internal/db"
	"muvon/internal/secret"
	"muvon/internal/waf"
	wafgrpc "muvon/internal/waf/grpcserver"
	pb "muvon/proto/wafpb"
)

func main() {
	var (
		dsn           = flag.String("dsn", envOr("MUWAF_DSN", "postgres://dialog:dialog@localhost:5432/dialog?sslmode=disable"), "PostgreSQL connection string")
		socketPath    = flag.String("socket", envOr("MUWAF_SOCKET", "/tmp/muwaf.sock"), "Unix socket path for gRPC")
		logLevel      = flag.String("log-level", envOr("MUWAF_LOG_LEVEL", "info"), "Log level")
		encryptionKey = flag.String("encryption-key", envOr("MUVON_ENCRYPTION_KEY", ""), "AES-256-GCM encryption key for secrets in DB")
	)
	flag.Parse()
	setupLogger(*logLevel)

	slog.Info("muWAF starting", "socket", *socketPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Database
	database, err := db.New(ctx, *dsn, "muwaf")
	if err != nil {
		slog.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	if err := database.RunMigrations(ctx); err != nil {
		slog.Error("migrations failed", "error", err)
		os.Exit(1)
	}

	// WAF Engine
	engine := waf.NewEngine(database)
	if err := engine.Start(ctx); err != nil {
		slog.Error("waf engine start failed", "error", err)
		os.Exit(1)
	}

	// Central config — muWAF runs out-of-process, so poll central settings.
	box := secret.NewBox(*encryptionKey)
	cfgHolder := config.NewHolder(config.NewDBSource(database, box), box)
	cfgHolder.OnReload(func(cfg *config.Config) {
		engine.ReloadConfig(wafConfigFromGlobal(cfg.Global))
	})
	if err := cfgHolder.Init(ctx); err != nil {
		slog.Warn("waf config init failed, using defaults", "error", err)
	}
	go pollWAFConfig(ctx, cfgHolder)

	// gRPC server on Unix socket
	os.Remove(*socketPath) // clean up stale socket
	lis, err := net.Listen("unix", *socketPath)
	if err != nil {
		slog.Error("unix socket listen failed", "error", err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer()
	wafSrv := wafgrpc.New(engine, database)
	pb.RegisterWafServiceServer(grpcServer, wafSrv)

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig)
		grpcServer.GracefulStop()
		engine.Stop(ctx)
		cancel()
	}()

	slog.Info("muWAF gRPC server listening", "socket", *socketPath)
	if err := grpcServer.Serve(lis); err != nil {
		slog.Error("gRPC server error", "error", err)
		os.Exit(1)
	}

	slog.Info("muWAF shutdown complete")
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

func pollWAFConfig(ctx context.Context, holder *config.Holder) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reloadCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := holder.Reload(reloadCtx)
			cancel()
			if err != nil {
				slog.Warn("waf config reload failed", "error", err)
			}
		}
	}
}

func wafConfigFromGlobal(g config.GlobalConfig) *waf.WafConfig {
	return &waf.WafConfig{
		EnabledGlobal:          g.WafEnabledGlobal,
		DetectionOnly:          g.WafDetectionOnly,
		ThresholdLog:           g.WafScoreThresholdLog,
		ThresholdRateLimit:     g.WafScoreThresholdRateLimit,
		ThresholdBlock:         g.WafScoreThresholdBlock,
		ThresholdTempBan:       g.WafScoreThresholdTempBan,
		ThresholdBan:           g.WafScoreThresholdBan,
		IPScoreDecayPerHour:    g.WafIPScoreDecayPerHour,
		IPScoreWindowHours:     g.WafIPScoreWindowHours,
		TempBanDurationMinutes: g.WafTempBanDurationMinutes,
		PatternCacheTTLSeconds: g.WafPatternCacheTTLSeconds,
		VTApiKey:               g.WafVTApiKey,
		VTTimeoutSeconds:       g.WafVTTimeoutSeconds,
		VTCacheTTLHours:        g.WafVTCacheTTLHours,
		VTScoreContribution:    g.WafVTScoreContribution,
		MaxBodyInspectBytes:    g.WafMaxBodyInspectBytes,
		NormalizationMaxIter:   g.WafNormalizationMaxIter,
	}
}
