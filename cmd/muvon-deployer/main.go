package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"muvon/internal/db"
	"muvon/internal/deployer"
)

func main() {
	var (
		dsn          = flag.String("dsn", envOr("MUVON_DSN", "postgres://muvon:muvon@localhost:5432/muvon?sslmode=disable"), "PostgreSQL connection string")
		dockerHost   = flag.String("docker-host", envOr("MUVON_DOCKER_HOST", "unix:///var/run/docker.sock"), "Docker API host")
		pollInterval = flag.Duration("poll", envDuration("MUVON_DEPLOYER_POLL_INTERVAL", 5*time.Second), "Deployment poll interval")
		logLevel     = flag.String("log-level", envOr("MUVON_LOG_LEVEL", "info"), "Log level")
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

	slog.Info("muvon deployer starting", "docker_host", *dockerHost, "poll_interval", pollInterval.String())
	service := deployer.NewService(database, dockerClient, *pollInterval)
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
