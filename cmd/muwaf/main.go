package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	"muvon/internal/db"
	"muvon/internal/waf"
	wafgrpc "muvon/internal/waf/grpcserver"
	pb "muvon/proto/wafpb"
)

func main() {
	var (
		dsn        = flag.String("dsn", envOr("MUWAF_DSN", "postgres://dialog:dialog@localhost:5432/dialog?sslmode=disable"), "PostgreSQL connection string")
		socketPath = flag.String("socket", envOr("MUWAF_SOCKET", "/tmp/muwaf.sock"), "Unix socket path for gRPC")
		logLevel   = flag.String("log-level", envOr("MUWAF_LOG_LEVEL", "info"), "Log level")
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
