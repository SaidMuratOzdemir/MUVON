package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"muvon/internal/db"
	"muvon/internal/deployer"
	deployergrpc "muvon/internal/deployer/grpcserver"
	pb "muvon/proto/deployerpb"
)

func main() {
	var (
		dsn          = flag.String("dsn", envOr("MUVON_DSN", "postgres://muvon:muvon@localhost:5432/muvon?sslmode=disable"), "PostgreSQL connection string")
		dockerHost   = flag.String("docker-host", envOr("MUVON_DOCKER_HOST", "unix:///var/run/docker.sock"), "Docker API host")
		pollInterval = flag.Duration("poll", envDuration("MUVON_DEPLOYER_POLL_INTERVAL", 5*time.Second), "Deployment poll interval")
		logLevel     = flag.String("log-level", envOr("MUVON_LOG_LEVEL", "info"), "Log level")
		// gRPC introspection surface — admin gateway dials this to render
		// the container picker and the live tail. Keep it Unix-only so
		// public-facing muvon never sees the Docker socket.
		grpcSocket = flag.String("grpc-socket", envOr("MUVON_DEPLOYER_SOCKET", "/run/muvon/deployer.sock"), "Unix socket path for the deployer gRPC service")
		// Live-tail viewer caps. Defaults guard against UI misuse: 4
		// concurrent tabs per container is plenty, 64 global is enough
		// for a small ops team.
		maxViewersPerContainer = flag.Int("max-viewers-per-container", intEnvOr("MUVON_CONTAINER_LOG_MAX_VIEWERS_PER_CONTAINER", 4), "Concurrent live-tail viewers allowed per container")
		maxViewersGlobal       = flag.Int("max-viewers-global", intEnvOr("MUVON_CONTAINER_LOG_MAX_VIEWERS_GLOBAL", 64), "Concurrent live-tail viewers allowed globally")
		maxLine                = flag.Int("max-line", intEnvOr("MUVON_CONTAINER_LOG_MAX_LINE", 16384), "Max bytes per emitted log line; longer lines split with truncated=true")
	)
	flag.Parse()
	setupLogger(*logLevel)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	database, err := db.New(ctx, *dsn, "muvon")
	if err != nil {
		slog.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	dockerClient, err := deployer.NewDockerClient(*dockerHost)
	if err != nil {
		slog.Error("docker client failed", "error", err)
		os.Exit(1)
	}

	slog.Info("muvon deployer starting",
		"docker_host", *dockerHost,
		"poll_interval", pollInterval.String(),
		"grpc_socket", *grpcSocket)

	service := deployer.NewService(database, dockerClient, *pollInterval)

	// gRPC server — Unix-only. Mirrors muwaf/dialog-siem startup shape.
	if err := os.MkdirAll(parentDir(*grpcSocket), 0o755); err != nil {
		slog.Warn("create gRPC socket dir failed", "path", parentDir(*grpcSocket), "error", err)
	}
	_ = os.Remove(*grpcSocket)
	lis, err := net.Listen("unix", *grpcSocket)
	if err != nil {
		slog.Error("unix socket listen failed", "path", *grpcSocket, "error", err)
		os.Exit(1)
	}
	// Make the socket world-readable/writable so the muvon container
	// (different uid from deployer's root) can connect via the shared
	// tmpfs volume. Aligns with the existing muwaf/dialog sockets.
	_ = os.Chmod(*grpcSocket, 0o666)

	grpcServer := grpc.NewServer()
	deployerSrv := deployergrpc.New(dockerClient, *maxViewersPerContainer, *maxViewersGlobal, *maxLine)
	pb.RegisterDeployerServiceServer(grpcServer, deployerSrv)

	// Wire MarkTick into the deployer's main loop so Health reports
	// freshness rather than just liveness.
	service.SetOnTick(deployerSrv.MarkTick)

	go func() {
		<-ctx.Done()
		slog.Info("muvon-deployer shutting down")
		grpcServer.GracefulStop()
	}()

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			slog.Error("muvon-deployer gRPC serve failed", "error", err)
			cancel()
		}
	}()

	if err := service.Run(ctx); err != nil && ctx.Err() == nil {
		slog.Error("muvon deployer stopped", "error", err)
		os.Exit(1)
	}
}

func setupLogger(level string) {
	var lvl slog.Level
	switch strings.ToLower(level) {
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

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
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

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	if seconds, err := strconv.Atoi(v); err == nil {
		return time.Duration(seconds) * time.Second
	}
	return def
}

func parentDir(p string) string {
	if i := strings.LastIndex(p, "/"); i > 0 {
		return p[:i]
	}
	return "."
}
