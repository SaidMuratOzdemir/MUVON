package config

import "context"

// Source loads configuration from a backend (DB or central server).
type Source interface {
	Load(ctx context.Context) (*Config, error)
}
