package config

import (
	"context"

	"muvon/internal/db"
	"muvon/internal/secret"
)

// DBSource loads configuration from PostgreSQL. Used by the central server.
type DBSource struct {
	database *db.DB
	box      *secret.Box
}

func NewDBSource(database *db.DB, box *secret.Box) *DBSource {
	return &DBSource{database: database, box: box}
}

func (s *DBSource) Load(ctx context.Context) (*Config, error) {
	return LoadFromDB(ctx, s.database, s.box)
}
