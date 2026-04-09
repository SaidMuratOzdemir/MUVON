package db

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct {
	Pool   *pgxpool.Pool
	Schema string // active schema name (muvon, muwaf, dialog)
}

// New creates a database connection pool.
// schema sets the PostgreSQL search_path so each product uses its own namespace.
// Pass "" for the default public schema (legacy/monolithic mode).
func New(ctx context.Context, dsn string, schema string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("db: parse config: %w", err)
	}

	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second

	// Set search_path so all queries use the product's schema by default
	if schema != "" {
		cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("db: connect: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}

	// Create schema if it doesn't exist
	if schema != "" {
		if _, err := pool.Exec(ctx, fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema)); err != nil {
			pool.Close()
			return nil, fmt.Errorf("db: create schema %s: %w", schema, err)
		}
	}

	slog.Info("database connected", "host", cfg.ConnConfig.Host, "database", cfg.ConnConfig.Database, "schema", schema)
	return &DB{Pool: pool, Schema: schema}, nil
}

func (d *DB) Close() {
	d.Pool.Close()
}

func (d *DB) Health(ctx context.Context) error {
	return d.Pool.Ping(ctx)
}
