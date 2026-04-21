package db

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct {
	Pool   *pgxpool.Pool
	Schema string // active schema name (muvon, muwaf, dialog)
}

// New creates a database connection pool.
//
// The primary schema is always first in search_path, so writes land where
// the caller expects. Additional schemas go after — dialog-siem uses this
// to read the shared muvon config tables (hosts, routes, deploy_*) without
// qualifying every query. public remains last so pg extensions live in
// their canonical place.
//
// Passing "" as primary falls back to the default search_path (legacy).
func New(ctx context.Context, dsn string, primary string, additional ...string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("db: parse config: %w", err)
	}

	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second

	if primary != "" {
		parts := append([]string{primary}, additional...)
		parts = append(parts, "public")
		seen := make(map[string]bool, len(parts))
		uniq := parts[:0]
		for _, p := range parts {
			if p != "" && !seen[p] {
				seen[p] = true
				uniq = append(uniq, p)
			}
		}
		cfg.ConnConfig.RuntimeParams["search_path"] = strings.Join(uniq, ",")
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("db: connect: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}

	// Create every schema we declared in search_path. We only own the
	// primary one (writes), but it's harmless to ensure the extras are
	// there too — they usually are, since some other binary created them,
	// but a fresh install where services start in any order needs this.
	for _, s := range append([]string{primary}, additional...) {
		if s == "" {
			continue
		}
		if _, err := pool.Exec(ctx, fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", s)); err != nil {
			pool.Close()
			return nil, fmt.Errorf("db: create schema %s: %w", s, err)
		}
	}

	slog.Info("database connected",
		"host", cfg.ConnConfig.Host,
		"database", cfg.ConnConfig.Database,
		"schema", primary,
		"search_path", cfg.ConnConfig.RuntimeParams["search_path"])
	return &DB{Pool: pool, Schema: primary}, nil
}

func (d *DB) Close() {
	d.Pool.Close()
}

func (d *DB) Health(ctx context.Context) error {
	return d.Pool.Ping(ctx)
}
