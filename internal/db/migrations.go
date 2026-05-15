package db

import (
	"context"
	"fmt"
	"log/slog"
)

// RunMigrations runs each migration exactly once, tracked in schema_migrations.
// On first install all migrations run. On subsequent startups only new ones run.
// Schema filtering: if Schema is set, only product-matching or shared migrations run.
func (d *DB) RunMigrations(ctx context.Context) error {
	slog.Info("running database migrations", "schema", d.Schema)

	// Ensure the migration tracking table exists (idempotent, no data loss).
	if _, err := d.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name       TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("migrations: create tracking table: %w", err)
	}

	// Load already-applied migration names.
	rows, err := d.Pool.Query(ctx, `SELECT name FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("migrations: load applied: %w", err)
	}
	applied := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return fmt.Errorf("migrations: scan applied: %w", err)
		}
		applied[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("migrations: read applied: %w", err)
	}

	count := 0
	for _, m := range migrations {
		if d.Schema != "" && m.product != "" && m.product != d.Schema {
			continue
		}
		if applied[m.name] {
			continue // already applied on a previous startup
		}

		slog.Info("applying migration", "name", m.name, "product", m.product)
		tx, err := d.Pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("migrations: begin tx for %s: %w", m.name, err)
		}

		if _, err := tx.Exec(ctx, m.sql); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("migrations: %s: %w", m.name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, m.name); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("migrations: record %s: %w", m.name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("migrations: commit %s: %w", m.name, err)
		}
		count++
	}

	slog.Info("migrations completed", "applied", count, "schema", d.Schema)
	return nil
}

type migration struct {
	name    string
	product string // "muvon", "dialog", or "" for shared/all
	sql     string
}

var migrations = []migration{
	// ── Extensions ──
	{
		name: "create_extensions", product: "",
		sql: `
CREATE EXTENSION IF NOT EXISTS pg_uuidv7;
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
CREATE EXTENSION IF NOT EXISTS pg_search;
CREATE OR REPLACE FUNCTION gen_uuidv7() RETURNS UUID AS $$ SELECT uuidv7(); $$ LANGUAGE SQL;`,
	},
	// ── MUVON (Edge Gateway) Tables ──
	{
		name: "create_hosts", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS hosts (
    id          SERIAL PRIMARY KEY,
    domain      TEXT NOT NULL UNIQUE,
    is_active   BOOLEAN DEFAULT true,
    force_https BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ DEFAULT now(),
    updated_at  TIMESTAMPTZ DEFAULT now()
);`,
	},
	{
		name: "create_routes", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS routes (
    id                  SERIAL PRIMARY KEY,
    host_id             INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    path_prefix         TEXT NOT NULL DEFAULT '/',
    route_type          TEXT NOT NULL CHECK (route_type IN ('proxy', 'static', 'redirect')),
    backend_url         TEXT,
    backend_urls        TEXT[] NOT NULL DEFAULT '{}',
    static_root         TEXT,
    redirect_url        TEXT,
    strip_prefix        BOOLEAN DEFAULT false,
    rewrite_pattern     TEXT,
    rewrite_to          TEXT,
    priority            INTEGER DEFAULT 0,
    is_active           BOOLEAN DEFAULT true,
    log_enabled         BOOLEAN NOT NULL DEFAULT true,
    rate_limit_rps      INTEGER NOT NULL DEFAULT 0,
    rate_limit_burst    INTEGER NOT NULL DEFAULT 0,
    req_headers_add     JSONB NOT NULL DEFAULT '{}',
    req_headers_del     TEXT[] NOT NULL DEFAULT '{}',
    resp_headers_add    JSONB NOT NULL DEFAULT '{}',
    resp_headers_del    TEXT[] NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ DEFAULT now(),
    updated_at          TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_routes_host_id ON routes (host_id, priority DESC);`,
	},
	{
		name: "create_tls_certificates", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS tls_certificates (
    id          SERIAL PRIMARY KEY,
    domain      TEXT NOT NULL,
    cert_pem    BYTEA NOT NULL,
    key_pem     BYTEA NOT NULL,
    issuer      TEXT NOT NULL DEFAULT 'letsencrypt',
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT tls_certificates_domain_issuer_key UNIQUE (domain, issuer)
);
CREATE INDEX IF NOT EXISTS idx_tls_certificates_domain ON tls_certificates (domain);`,
	},
	{
		name: "create_admin_users", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS admin_users (
    id            SERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_active     BOOLEAN DEFAULT true,
    created_at    TIMESTAMPTZ DEFAULT now()
);`,
	},
	{
		name: "create_acme_cache", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS acme_cache (
    key        TEXT PRIMARY KEY,
    data       BYTEA NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now()
);`,
	},
	{
		name: "create_admin_audit_log", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id          BIGSERIAL PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    admin_user  TEXT NOT NULL,
    action      TEXT NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    detail      JSONB,
    ip          TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON admin_audit_log (timestamp DESC);`,
	},
	// ── Central Settings (stored in muvon schema) ──
	{
		name: "create_settings", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       JSONB NOT NULL,
    updated_at  TIMESTAMPTZ DEFAULT now()
);`,
	},
	// ── diaLOG (SIEM) Tables — UUIDv7 + TimescaleDB Hypertables ──
	{
		name: "create_http_logs_hypertable", product: "dialog",
		sql: `
CREATE TABLE IF NOT EXISTS http_logs (
    id                UUID DEFAULT gen_uuidv7() NOT NULL,
    timestamp         TIMESTAMPTZ NOT NULL DEFAULT now(),
    host              TEXT NOT NULL,
    client_ip         TEXT NOT NULL,
    method            TEXT NOT NULL,
    path              TEXT NOT NULL,
    query_string      TEXT,
    request_headers   JSONB,
    response_status   INTEGER NOT NULL,
    response_headers  JSONB,
    response_time_ms  INTEGER,
    request_size      INTEGER,
    response_size     INTEGER,
    user_agent        TEXT,
    error             TEXT,
    is_starred        BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (id, timestamp)
);
SELECT create_hypertable('http_logs', by_range('timestamp', INTERVAL '1 day'), if_not_exists => true);`,
	},
	{
		name: "create_http_log_bodies_hypertable", product: "dialog",
		sql: `
CREATE TABLE IF NOT EXISTS http_log_bodies (
    id                    UUID DEFAULT gen_uuidv7() NOT NULL,
    log_id                UUID NOT NULL,
    timestamp             TIMESTAMPTZ NOT NULL,
    request_body          TEXT,
    response_body         TEXT,
    is_request_truncated  BOOLEAN DEFAULT false,
    is_response_truncated BOOLEAN DEFAULT false,
    PRIMARY KEY (id, timestamp)
);
SELECT create_hypertable('http_log_bodies', by_range('timestamp', INTERVAL '1 day'), if_not_exists => true);`,
	},
	{
		name: "create_log_notes", product: "dialog",
		sql: `
CREATE TABLE IF NOT EXISTS log_notes (
    log_id     UUID PRIMARY KEY,
    note       TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by TEXT NOT NULL DEFAULT 'admin'
);`,
	},
	{
		name: "create_dialog_indexes", product: "dialog",
		sql: `
CREATE INDEX IF NOT EXISTS idx_http_logs_host_ts ON http_logs (host, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_http_logs_status_ts ON http_logs (response_status, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_http_logs_client_ip ON http_logs (client_ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_http_log_bodies_log_id ON http_log_bodies (log_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_http_logs_starred ON http_logs (is_starred) WHERE is_starred = true;`,
	},
	{
		name: "create_dialog_bm25_index", product: "dialog",
		sql: `
CREATE INDEX IF NOT EXISTS http_logs_search ON http_logs
USING bm25 (id, path, host, user_agent, client_ip)
WITH (key_field = 'id');`,
	},
	{
		name: "add_dialog_retention_policy", product: "dialog",
		sql: `
SELECT add_retention_policy('http_logs', INTERVAL '30 days', if_not_exists => true);
SELECT add_retention_policy('http_log_bodies', INTERVAL '30 days', if_not_exists => true);`,
	},
	{
		name: "add_dialog_compression", product: "dialog",
		sql: `
ALTER TABLE http_logs SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'host',
    timescaledb.compress_orderby = 'timestamp DESC'
);
SELECT add_compression_policy('http_logs', INTERVAL '7 days', if_not_exists => true);

ALTER TABLE http_log_bodies SET (
    timescaledb.compress,
    timescaledb.compress_orderby = 'timestamp DESC'
);
SELECT add_compression_policy('http_log_bodies', INTERVAL '7 days', if_not_exists => true);`,
	},
	// ── diaLOG: SIEM enrichment columns ──
	{
		name: "add_identity_geo_columns", product: "dialog",
		sql: `
ALTER TABLE http_logs ADD COLUMN IF NOT EXISTS user_identity JSONB;
ALTER TABLE http_logs ADD COLUMN IF NOT EXISTS country TEXT;
ALTER TABLE http_logs ADD COLUMN IF NOT EXISTS city TEXT;`,
	},
	// Per-host JWT identity overrides. When a host enables JWT identity,
	// the pipeline enricher uses that host's secret/claims instead of the
	// global one. This lets a single MUVON front multiple tenant apps
	// that sign with different secrets (e.g. one Django SECRET_KEY per
	// customer). Null / empty values fall back to the global settings so
	// operators can start global and move to per-host incrementally.
	{
		name: "add_hosts_jwt_columns", product: "muvon",
		sql: `
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS jwt_identity_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS jwt_identity_mode    TEXT    NOT NULL DEFAULT 'verify';
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS jwt_claims           TEXT    NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS jwt_secret           TEXT    NOT NULL DEFAULT '';`,
	},
	// Swap BM25 for pg_trgm trigram GIN indexes. pg_search's BM25 operator
	// does not propagate to TimescaleDB hypertable chunks in the installed
	// pg_search version (0.22.5) — chunk-level queries match, hypertable
	// root queries return zero. Trigram GIN on each searchable column
	// works natively with hypertables, and ILIKE '%term%' against a
	// handful of columns is cheap enough at tenant scale.
	{
		name: "drop_dialog_bm25_index", product: "dialog",
		sql: `DROP INDEX IF EXISTS http_logs_search;`,
	},
	{
		name: "add_http_logs_fts_trgm_indexes", product: "dialog",
		sql: `
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS idx_http_logs_path_trgm       ON http_logs USING gin (path       gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_http_logs_host_trgm       ON http_logs USING gin (host       gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_http_logs_user_agent_trgm ON http_logs USING gin (user_agent gin_trgm_ops) WHERE user_agent IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_http_logs_client_ip_trgm  ON http_logs USING gin (client_ip  gin_trgm_ops);`,
	},
	// Search also has to reach the enriched identity (JWT claim values
	// like user_id or email) and the captured bodies (TC Kimlik, IBAN,
	// anything the app sends in JSON). Trigram indexes on the JSONB
	// text-cast and the body columns keep those ILIKE lookups
	// hypertable-safe and fast at tenant scale.
	{
		name: "add_http_logs_identity_body_trgm_indexes", product: "dialog",
		sql: `
CREATE INDEX IF NOT EXISTS idx_http_logs_user_identity_trgm
    ON http_logs USING gin ((user_identity::text) gin_trgm_ops)
    WHERE user_identity IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_http_log_bodies_request_trgm
    ON http_log_bodies USING gin (request_body gin_trgm_ops)
    WHERE request_body IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_http_log_bodies_response_trgm
    ON http_log_bodies USING gin (response_body gin_trgm_ops)
    WHERE response_body IS NOT NULL;`,
	},
	// Fast JSONB containment for user_identity. Lets us answer
	// "show me every request where claims @> {email: alice}" without a full
	// scan over the chunks, and the same index serves sub / name / role
	// lookups too because jsonb_path_ops supports the @> operator on any
	// nested path.
	{
		name: "add_http_logs_user_identity_gin", product: "dialog",
		sql: `
CREATE INDEX IF NOT EXISTS idx_http_logs_user_identity_gin
    ON http_logs USING gin (user_identity jsonb_path_ops)
    WHERE user_identity IS NOT NULL;`,
	},
	// ── diaLOG: Alerts table ──
	{
		name: "create_alerts_table", product: "dialog",
		sql: `
CREATE TABLE IF NOT EXISTS alerts (
    id          UUID DEFAULT gen_uuidv7() NOT NULL,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT now(),
    rule        TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('info','warning','critical')),
    title       TEXT NOT NULL,
    detail      JSONB,
    source_ip   TEXT,
    host        TEXT,
    fingerprint TEXT NOT NULL,
    notified    BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (id, timestamp)
);
SELECT create_hypertable('alerts', by_range('timestamp', INTERVAL '1 day'), if_not_exists => true);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_ts ON alerts (rule, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity_ts ON alerts (severity, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts (fingerprint, timestamp DESC);
SELECT add_retention_policy('alerts', INTERVAL '30 days', if_not_exists => true);
ALTER TABLE alerts SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'rule',
    timescaledb.compress_orderby = 'timestamp DESC'
);
SELECT add_compression_policy('alerts', INTERVAL '7 days', if_not_exists => true);`,
	},
	// ── Seed Settings ──
	{
		name: "seed_default_settings", product: "muvon",
		sql: `
INSERT INTO settings (key, value) VALUES
    ('retention_days', '30'),
    ('max_body_capture_size', '65536'),
    ('log_pipeline_buffer', '10000'),
    ('log_batch_size', '1000'),
    ('log_flush_interval_ms', '2000'),
    ('log_worker_count', '4'),
    ('enable_body_capture', 'true'),
    ('letsencrypt_staging', 'false'),
    ('letsencrypt_email', '""'),
    ('jwt_identity_enabled', 'false'),
    ('jwt_identity_mode', '"verify"'),
    ('jwt_claims', '"sub,email,name,role"'),
    ('jwt_secret', '""'),
    ('geoip_enabled', 'false'),
    ('geoip_db_path', '""'),
    ('alerting_enabled', 'false'),
    ('alerting_slack_webhook', '""'),
    ('alerting_smtp_host', '""'),
    ('alerting_smtp_port', '587'),
    ('alerting_smtp_username', '""'),
    ('alerting_smtp_password', '""'),
    ('alerting_smtp_from', '""'),
    ('alerting_smtp_to', '""'),
    ('alerting_cooldown_seconds', '300')
ON CONFLICT (key) DO NOTHING;`,
	},
	{
		name: "fix_tls_certificates_uniqueness", product: "muvon",
		sql: `
UPDATE tls_certificates
SET domain = lower(domain)
WHERE domain <> lower(domain);

DELETE FROM tls_certificates t
USING (
    SELECT id
    FROM (
        SELECT id,
               row_number() OVER (
                   PARTITION BY domain, issuer
                   ORDER BY expires_at DESC, created_at DESC, id DESC
               ) AS rn
        FROM tls_certificates
    ) ranked
    WHERE rn > 1
) dupes
WHERE t.id = dupes.id;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'tls_certificates'::regclass
          AND contype = 'u'
          AND conname = 'tls_certificates_domain_issuer_key'
    ) THEN
        RETURN;
    END IF;

    IF to_regclass('idx_tls_certificates_domain_issuer_unique') IS NULL THEN
        EXECUTE 'CREATE UNIQUE INDEX idx_tls_certificates_domain_issuer_unique ON tls_certificates (domain, issuer)';
    END IF;
END $$;`,
	},
	// ── X-Accel-Redirect support ──
	{
		name: "add_routes_accel_root", product: "muvon",
		sql: `ALTER TABLE routes ADD COLUMN IF NOT EXISTS accel_root TEXT;`,
	},
	{
		name: "add_routes_accel_signed_secret", product: "muvon",
		sql: `ALTER TABLE routes ADD COLUMN IF NOT EXISTS accel_signed_secret TEXT;`,
	},
	// ── Per-route body limit + timeout ──
	{
		name: "add_routes_max_body_bytes", product: "muvon",
		sql: `ALTER TABLE routes ADD COLUMN IF NOT EXISTS max_body_bytes BIGINT NOT NULL DEFAULT 0;`,
	},
	{
		name: "add_routes_timeout_seconds", product: "muvon",
		sql: `ALTER TABLE routes ADD COLUMN IF NOT EXISTS timeout_seconds INT NOT NULL DEFAULT 0;`,
	},
	// ── Per-route CORS ──
	{
		name: "add_routes_cors", product: "muvon",
		sql: `
ALTER TABLE routes ADD COLUMN IF NOT EXISTS cors_enabled     BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE routes ADD COLUMN IF NOT EXISTS cors_origins     TEXT    NOT NULL DEFAULT '*';
ALTER TABLE routes ADD COLUMN IF NOT EXISTS cors_methods     TEXT    NOT NULL DEFAULT 'GET,POST,PUT,DELETE,OPTIONS,PATCH';
ALTER TABLE routes ADD COLUMN IF NOT EXISTS cors_headers     TEXT    NOT NULL DEFAULT '*';
ALTER TABLE routes ADD COLUMN IF NOT EXISTS cors_max_age     INT     NOT NULL DEFAULT 86400;
ALTER TABLE routes ADD COLUMN IF NOT EXISTS cors_credentials BOOLEAN NOT NULL DEFAULT false;`,
	},
	// ── Per-route custom error pages ──
	{
		name: "add_routes_error_pages", product: "muvon",
		sql: `
ALTER TABLE routes ADD COLUMN IF NOT EXISTS error_page_4xx TEXT;
ALTER TABLE routes ADD COLUMN IF NOT EXISTS error_page_5xx TEXT;`,
	},
	// ── Per-host trusted proxies for X-Forwarded-For ──
	{
		name: "add_hosts_trusted_proxies", product: "muvon",
		sql: `ALTER TABLE hosts ADD COLUMN IF NOT EXISTS trusted_proxies TEXT[] NOT NULL DEFAULT '{}';`,
	},
	// ── Managed application deploys ──
	{
		name: "create_deploy_projects", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS deploy_projects (
    id             SERIAL PRIMARY KEY,
    slug           TEXT NOT NULL UNIQUE,
    name           TEXT NOT NULL,
    source_repo    TEXT NOT NULL DEFAULT '',
    webhook_secret TEXT NOT NULL DEFAULT '',
    is_active      BOOLEAN NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ DEFAULT now(),
    updated_at     TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_deploy_projects_slug ON deploy_projects (slug) WHERE is_active;`,
	},
	{
		name: "create_deploy_components", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS deploy_components (
    id                         SERIAL PRIMARY KEY,
    project_id                 INTEGER NOT NULL REFERENCES deploy_projects(id) ON DELETE CASCADE,
    slug                       TEXT NOT NULL,
    name                       TEXT NOT NULL,
    source_repo                TEXT NOT NULL DEFAULT '',
    image_repo                 TEXT NOT NULL,
    internal_port              INTEGER NOT NULL,
    health_path                TEXT NOT NULL DEFAULT '/',
    health_expected_status     INTEGER NOT NULL DEFAULT 200,
    migration_command          TEXT[] NOT NULL DEFAULT '{}',
    restart_retries            INTEGER NOT NULL DEFAULT 1,
    drain_timeout_seconds      INTEGER NOT NULL DEFAULT 30,
    long_drain_timeout_seconds INTEGER NOT NULL DEFAULT 300,
    networks                   TEXT[] NOT NULL DEFAULT '{}',
    env_file_path              TEXT NOT NULL DEFAULT '',
    env                        JSONB NOT NULL DEFAULT '{}',
    is_routable                BOOLEAN NOT NULL DEFAULT true,
    created_at                 TIMESTAMPTZ DEFAULT now(),
    updated_at                 TIMESTAMPTZ DEFAULT now(),
    UNIQUE (project_id, slug)
);
CREATE INDEX IF NOT EXISTS idx_deploy_components_project ON deploy_components (project_id);`,
	},
	{
		name: "create_deploy_releases", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS deploy_releases (
    id          UUID PRIMARY KEY DEFAULT gen_uuidv7(),
    project_id  INTEGER NOT NULL REFERENCES deploy_projects(id) ON DELETE CASCADE,
    release_id  TEXT NOT NULL,
    repo        TEXT NOT NULL DEFAULT '',
    branch      TEXT NOT NULL DEFAULT '',
    commit_sha  TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','succeeded','failed','rolled_back')),
    created_at  TIMESTAMPTZ DEFAULT now(),
    updated_at  TIMESTAMPTZ DEFAULT now(),
    UNIQUE (project_id, release_id)
);
CREATE INDEX IF NOT EXISTS idx_deploy_releases_project_created ON deploy_releases (project_id, created_at DESC);`,
	},
	{
		name: "create_deploy_release_components", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS deploy_release_components (
    release_uuid UUID NOT NULL REFERENCES deploy_releases(id) ON DELETE CASCADE,
    component_id INTEGER NOT NULL REFERENCES deploy_components(id) ON DELETE CASCADE,
    image_ref    TEXT NOT NULL,
    image_digest TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','succeeded','failed')),
    created_at   TIMESTAMPTZ DEFAULT now(),
    updated_at   TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (release_uuid, component_id)
);
CREATE INDEX IF NOT EXISTS idx_deploy_release_components_component ON deploy_release_components (component_id);`,
	},
	{
		name: "create_deploy_instances", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS deploy_instances (
    id               UUID PRIMARY KEY DEFAULT gen_uuidv7(),
    component_id     INTEGER NOT NULL REFERENCES deploy_components(id) ON DELETE CASCADE,
    release_uuid     UUID REFERENCES deploy_releases(id) ON DELETE SET NULL,
    container_id     TEXT NOT NULL DEFAULT '',
    container_name   TEXT NOT NULL DEFAULT '',
    backend_url      TEXT NOT NULL DEFAULT '',
    state            TEXT NOT NULL DEFAULT 'warming' CHECK (state IN ('warming','active','draining','unhealthy','stopped')),
    health_status    TEXT NOT NULL DEFAULT 'unknown',
    in_flight        INTEGER NOT NULL DEFAULT 0,
    last_error       TEXT NOT NULL DEFAULT '',
    started_at       TIMESTAMPTZ,
    drain_started_at TIMESTAMPTZ,
    stopped_at       TIMESTAMPTZ,
    created_at       TIMESTAMPTZ DEFAULT now(),
    updated_at       TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_deploy_instances_component_state ON deploy_instances (component_id, state);
CREATE INDEX IF NOT EXISTS idx_deploy_instances_release ON deploy_instances (release_uuid);`,
	},
	{
		name: "create_deployments", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS deployments (
    id           UUID PRIMARY KEY DEFAULT gen_uuidv7(),
    project_id   INTEGER NOT NULL REFERENCES deploy_projects(id) ON DELETE CASCADE,
    release_uuid UUID NOT NULL REFERENCES deploy_releases(id) ON DELETE CASCADE,
    release_id   TEXT NOT NULL,
    trigger      TEXT NOT NULL DEFAULT 'webhook',
    status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','succeeded','failed','rolled_back')),
    payload      JSONB NOT NULL DEFAULT '{}',
    error        TEXT NOT NULL DEFAULT '',
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ DEFAULT now(),
    updated_at   TIMESTAMPTZ DEFAULT now(),
    UNIQUE (project_id, release_uuid)
);
CREATE INDEX IF NOT EXISTS idx_deployments_status_created ON deployments (status, created_at);
CREATE INDEX IF NOT EXISTS idx_deployments_project_created ON deployments (project_id, created_at DESC);`,
	},
	{
		name: "create_deployment_events", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS deployment_events (
    id            BIGSERIAL PRIMARY KEY,
    deployment_id UUID NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    event_type    TEXT NOT NULL,
    message       TEXT NOT NULL DEFAULT '',
    detail        JSONB NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_deployment_events_deployment ON deployment_events (deployment_id, created_at);`,
	},
	{
		name: "add_routes_managed_component", product: "muvon",
		sql: `
ALTER TABLE routes ADD COLUMN IF NOT EXISTS managed_component_id INTEGER REFERENCES deploy_components(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_routes_managed_component ON routes (managed_component_id) WHERE managed_component_id IS NOT NULL;`,
	},
	// ── Agents (shared — both muvon and dialog need this) ──
	{
		name: "create_agents", product: "",
		sql: `
CREATE TABLE IF NOT EXISTS agents (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    api_key    TEXT NOT NULL UNIQUE,
    is_active  BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agents_api_key ON agents (api_key) WHERE is_active;`,
	},
	{
		name: "add_agents_last_seen_at", product: "",
		sql: `ALTER TABLE agents ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;`,
	},
	{
		name: "add_routes_static_spa", product: "muvon",
		sql: `ALTER TABLE routes ADD COLUMN IF NOT EXISTS static_spa BOOLEAN NOT NULL DEFAULT false;`,
	},
	// ── Refresh tokens (enterprise auth: short-lived access + long-lived refresh with rotation) ──
	{
		name: "add_admin_users_token_version", product: "muvon",
		sql: `ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0;`,
	},
	{
		name: "create_admin_refresh_tokens", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS admin_refresh_tokens (
    id           UUID NOT NULL DEFAULT gen_uuidv7(),
    user_id      INTEGER NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    token_hash   BYTEA NOT NULL,
    family_id    UUID NOT NULL,
    parent_id    UUID,
    issued_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    user_agent   TEXT,
    ip_address   TEXT,
    PRIMARY KEY (id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_refresh_tokens_hash    ON admin_refresh_tokens (token_hash);
CREATE INDEX IF NOT EXISTS        idx_admin_refresh_tokens_user    ON admin_refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS        idx_admin_refresh_tokens_family  ON admin_refresh_tokens (family_id);
CREATE INDEX IF NOT EXISTS        idx_admin_refresh_tokens_expires ON admin_refresh_tokens (expires_at);`,
	},
	// ── Alerts: acknowledgement metadata ──
	// An admin clicking "Acknowledge" on an alert row stops it from showing
	// up in the default "needs attention" view. The fingerprint cooldown
	// already suppresses notifications; ack is a workflow signal ("we're
	// aware, it's being handled"), not a dedup mechanism.
	{
		name: "add_alerts_acknowledged_columns", product: "dialog",
		sql: `
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acknowledged    BOOLEAN     NOT NULL DEFAULT false;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acknowledged_by TEXT;
CREATE INDEX IF NOT EXISTS idx_alerts_ack_timestamp
    ON alerts (acknowledged, timestamp DESC);`,
	},
	// ── Alerts: grouping + DB-backed cooldown ──
	// occurrences: how many times the same fingerprint has fired inside the
	//              most recent cooldown window (≥1, starts at 1 on insert).
	// last_seen_at: rolls forward on every duplicate; powers "last 15 events in
	//              the group" views in the UI.
	// notified_at: set to now() when a notifier actually dispatched. The index
	//              below lets the alert manager answer "did we notify this
	//              fingerprint in the last N seconds?" in O(log n) across every
	//              node — this is how multi-node cooldown stays consistent.
	//
	// TimescaleDB hypertables with compression enabled reject ADD COLUMN when
	// the default expression is non-constant (SQLSTATE 0A000). `now()` counts
	// as non-constant. The workaround is to add the column nullable, backfill
	// existing rows, then enforce NOT NULL + a constant default.
	{
		name: "add_alerts_grouping_columns", product: "dialog",
		sql: `
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS occurrences INTEGER;
UPDATE alerts SET occurrences = 1 WHERE occurrences IS NULL;
ALTER TABLE alerts ALTER COLUMN occurrences SET DEFAULT 1;
ALTER TABLE alerts ALTER COLUMN occurrences SET NOT NULL;

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;
UPDATE alerts SET last_seen_at = COALESCE(last_seen_at, timestamp, now());
ALTER TABLE alerts ALTER COLUMN last_seen_at SET NOT NULL;

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS notified_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint_notified
    ON alerts (fingerprint, notified_at DESC)
    WHERE notified_at IS NOT NULL;`,
	},
	// ── Correlation engine tunables ──
	// Everything is a setting so thresholds and path lists can be edited in
	// the admin panel without redeploying. auth_paths / sensitive_paths are
	// CSV because settings.value is JSONB but we already store CSV strings
	// elsewhere (jwt_claims) — keeping the convention.
	{
		name: "seed_correlation_settings", product: "muvon",
		sql: `
INSERT INTO settings (key, value) VALUES
    ('correlation_path_scan_distinct',        '10'),
    ('correlation_path_scan_window_seconds',  '120'),
    ('correlation_auth_brute_count',          '5'),
    ('correlation_auth_brute_window_seconds', '120'),
    ('correlation_auth_paths',                '"/login,/api/auth/login,/api/auth/login/,/api/authentication/login,/api/authentication/login/"'),
    ('correlation_error_spike_count',         '10'),
    ('correlation_error_spike_window_seconds','60'),
    ('correlation_anomaly_enabled',           'true'),
    ('correlation_anomaly_ratio',             '3.0'),
    ('correlation_anomaly_baseline_seconds',  '600'),
    ('correlation_anomaly_current_seconds',   '60'),
    ('correlation_anomaly_min_baseline',      '20'),
    ('correlation_sensitive_paths',           '""'),
    ('correlation_sensitive_threshold',       '10'),
    ('correlation_sensitive_window_seconds',  '300'),
    ('correlation_export_pattern',            '"(?i)(download|export|report|\\.pdf|\\.xlsx|\\.csv)"'),
    ('correlation_export_threshold',          '5'),
    ('correlation_export_window_seconds',     '300')
ON CONFLICT (key) DO NOTHING;`,
	},
	// One-shot cleanup for stored string settings whose JSON value got saved
	// with surrounding whitespace before the admin-side trim landed (a single
	// leading space in geoip_db_path silently disabled the loader for weeks).
	// We rebuild the JSONB scalar from a trimmed Go string via to_jsonb so
	// objects/numbers/booleans are left untouched even though jsonb_typeof
	// already filters them.
	{
		name: "trim_whitespace_in_string_settings", product: "muvon",
		sql: `
UPDATE settings
SET value = to_jsonb(btrim(value #>> '{}'))
WHERE jsonb_typeof(value) = 'string'
  AND value #>> '{}' <> btrim(value #>> '{}');`,
	},
	// Per-host identity_header_name: the request header to inspect for a
	// bearer-style identity token. Default "Authorization" matches RFC 6750
	// and our existing pipeline. We add this because some tenants
	// authenticate with a different header name (X-Auth-Token, X-Access-Token),
	// which previously left identity enrichment silent for that whole host.
	{
		name: "add_hosts_identity_header_name", product: "muvon",
		sql: `
ALTER TABLE hosts
  ADD COLUMN IF NOT EXISTS identity_header_name TEXT NOT NULL DEFAULT 'Authorization';`,
	},
	// running and when they last pulled/streamed it. Without these the only
	// signal we have is "is the agent alive now?" — no way to detect a
	// stuck agent that's still pinging but missed a config push, which is
	// exactly the scenario where agents drift apart from central.
	{
		name: "add_agents_observability_columns", product: "",
		sql: `
ALTER TABLE agents
  ADD COLUMN IF NOT EXISTS last_config_pull_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS config_version      TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS last_remote_addr    TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS last_user_agent     TEXT NOT NULL DEFAULT '';`,
	},
	// Per-host opt-in for raw-JWT capture. Off by default — storing the
	// signed token alongside the log row is a high-value secret if the DB
	// is ever exfiltrated, so admins must explicitly turn it on per host
	// (typically only for tenants where customer-support workflows need
	// to replay or decode the original token).
	{
		name: "add_hosts_store_raw_jwt", product: "muvon",
		sql: `
ALTER TABLE hosts
  ADD COLUMN IF NOT EXISTS store_raw_jwt BOOLEAN NOT NULL DEFAULT FALSE;`,
	},
	// Raw JWT column on the log row. Nullable + indexed-only for the
	// "is set" case so we can render a Reveal button without leaking the
	// token in list views. Existence of this column for hosts without
	// store_raw_jwt is harmless — the pipeline never populates it.
	{
		name: "add_http_logs_raw_jwt", product: "dialog",
		sql: `
ALTER TABLE http_logs
  ADD COLUMN IF NOT EXISTS raw_jwt TEXT;`,
	},
	// Per-component mount specs. Persistent storage (uploads, caches,
	// SQLite databases, etc.) must survive container replacement during
	// deploys; without an explicit mount, Django/etc. write into the
	// container's writable layer and the data is lost on the next
	// release. Stored as a JSONB array of Docker Engine API "Mount"
	// objects ({type,source,target,read_only,bind_options,volume_options})
	// — structured rather than legacy "host:container[:ro]" binds so we
	// can carry options (e.g. CreateMountpoint, named-volume labels)
	// without parsing strings. Empty array == no extra mounts (current
	// behaviour preserved).
	{
		name: "add_deploy_components_mounts", product: "muvon",
		sql: `
ALTER TABLE deploy_components
  ADD COLUMN IF NOT EXISTS mounts JSONB NOT NULL DEFAULT '[]'::jsonb;`,
	},
	// ── Container Logs ─────────────────────────────────────────────────────
	// Dimension table for every container the shipper has ever attached
	// to. Survives container deletion so the admin UI's picker can still
	// list "muvon-<project>-<component>-…" weeks after Docker removed it.
	// Tiny rows, no Timescale — retention here is much longer than the
	// hypertable's so a deployment can be looked up after the actual logs
	// have aged out.
	{
		name: "create_containers_dimension_table", product: "dialog",
		sql: `
CREATE TABLE IF NOT EXISTS containers (
    id              UUID PRIMARY KEY DEFAULT gen_uuidv7(),
    container_id    TEXT NOT NULL UNIQUE,
    container_name  TEXT NOT NULL,
    image           TEXT NOT NULL DEFAULT '',
    image_digest    TEXT NOT NULL DEFAULT '',
    project         TEXT,
    component       TEXT,
    release_id      TEXT,
    deployment_id   UUID,
    host_id         TEXT NOT NULL DEFAULT 'central',
    labels          JSONB NOT NULL DEFAULT '{}',
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    exit_code       INTEGER,
    last_log_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_containers_project_release ON containers (project, component, release_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_containers_started_at      ON containers (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_containers_finished_at     ON containers (finished_at DESC) WHERE finished_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_containers_host_id         ON containers (host_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_containers_release_only    ON containers (release_id, started_at DESC) WHERE release_id IS NOT NULL;`,
	},
	// container_logs hypertable. One row per stdout/stderr record. seq is
	// the shipper-assigned monotonic counter — protects ordering when two
	// lines share a microsecond. Trigram GIN on `line` + jsonb_path_ops
	// on `attrs` cover the common search patterns (free-text and
	// {level: ERROR}-style structured filters); BM25 deliberately avoided
	// after the http_logs experience (pg_search BM25 does not propagate
	// to hypertable chunks in 0.22.5).
	{
		name: "create_container_logs_hypertable", product: "dialog",
		sql: `
CREATE TABLE IF NOT EXISTS container_logs (
    id             UUID DEFAULT gen_uuidv7() NOT NULL,
    timestamp      TIMESTAMPTZ NOT NULL,
    received_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    host_id        TEXT NOT NULL DEFAULT 'central',
    container_id   TEXT NOT NULL,
    container_name TEXT NOT NULL,
    image          TEXT,
    project        TEXT,
    component      TEXT,
    release_id     TEXT,
    deployment_id  UUID,
    stream         TEXT NOT NULL CHECK (stream IN ('stdout','stderr')),
    line           TEXT NOT NULL,
    truncated      BOOLEAN NOT NULL DEFAULT FALSE,
    seq            BIGINT NOT NULL DEFAULT 0,
    attrs          JSONB,
    PRIMARY KEY (id, timestamp)
);
SELECT create_hypertable('container_logs', by_range('timestamp', INTERVAL '1 day'), if_not_exists => true);
CREATE INDEX IF NOT EXISTS idx_container_logs_container_ts ON container_logs (container_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_container_logs_project_ts   ON container_logs (project, component, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_container_logs_release_ts   ON container_logs (release_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_container_logs_deploy_ts    ON container_logs (deployment_id, timestamp DESC) WHERE deployment_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_container_logs_host_ts      ON container_logs (host_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_container_logs_line_trgm    ON container_logs USING gin (line gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_container_logs_attrs_gin    ON container_logs USING gin (attrs jsonb_path_ops) WHERE attrs IS NOT NULL;`,
	},
	// Compression after 7 days, drop after 30. segment_by container_id
	// keeps a single-container search inside one segment; the typical
	// "show me everything from backend-aef3a8a" path stays cheap.
	{
		name: "add_container_logs_compression_retention", product: "dialog",
		sql: `
ALTER TABLE container_logs SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'container_id',
    timescaledb.compress_orderby = 'timestamp DESC, seq DESC'
);
SELECT add_compression_policy('container_logs', INTERVAL '7 days', if_not_exists => true);
SELECT add_retention_policy('container_logs', INTERVAL '30 days', if_not_exists => true);`,
	},
	// Operatörün hangi env değişkenlerini "hassas" işaretlediğini saklar.
	// İşaretli key'lerin değerleri Env JSONB'sinde "enc:" prefix'iyle
	// secret.Box ciphertext olarak yazılır. UI bu key'leri masked gösterir
	// ve deployer container'a verirken decrypt eder.
	{
		name: "add_deploy_components_env_secret_keys", product: "muvon",
		sql: `ALTER TABLE deploy_components ADD COLUMN IF NOT EXISTS env_secret_keys TEXT[] NOT NULL DEFAULT '{}';`,
	},
	// Hybrid topology: a component (and its deployments) can live either
	// on the central MUVON host (agent_id NULL) or on an edge node where
	// an agent runs Docker (agent_id = agents.id). Filtering on this
	// column lets each deployer instance pick up only its own work.
	{
		name: "add_deploy_components_agent_id", product: "muvon",
		sql: `ALTER TABLE deploy_components ADD COLUMN IF NOT EXISTS agent_id TEXT REFERENCES agents(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_deploy_components_agent ON deploy_components (agent_id) WHERE agent_id IS NOT NULL;`,
	},
	{
		name: "add_deployments_agent_id", product: "muvon",
		sql: `ALTER TABLE deployments ADD COLUMN IF NOT EXISTS agent_id TEXT REFERENCES agents(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_deployments_agent_pending ON deployments (agent_id, status, created_at) WHERE status = 'pending';`,
	},
	// Per-host TLS strategy. 'off' = listener serves HTTP only; 'redirect'
	// = HTTP→HTTPS upgrade; 'auto' = ACME issuance; 'manual' = wait for
	// uploaded cert. Existing force_https=true rows map to 'redirect'.
	{
		name: "add_hosts_tls_mode", product: "muvon",
		sql: `ALTER TABLE hosts ADD COLUMN IF NOT EXISTS tls_mode TEXT NOT NULL DEFAULT 'auto'
              CHECK (tls_mode IN ('off','redirect','auto','manual'));
UPDATE hosts SET tls_mode = 'redirect' WHERE force_https = true AND tls_mode = 'auto';`,
	},
	// Component-level pause: when true the deployer refuses to spawn new
	// instances and drains existing ones. Distinct from deleting the
	// component — the config (env, image_repo, mounts) is preserved so
	// the operator can resume later without rebuilding it.
	{
		name: "add_deploy_components_paused", product: "muvon",
		sql: `ALTER TABLE deploy_components ADD COLUMN IF NOT EXISTS paused BOOLEAN NOT NULL DEFAULT false;`,
	},
	// Agent API keys move from plaintext to SHA-256 hash. The hash column
	// starts empty; the Go-side auth middleware lazily fills it on first
	// successful authentication (transparent migration — no admin action).
	// A later release will drop the plaintext column once usage telemetry
	// shows every active agent has been rehashed.
	{
		name: "add_agents_api_key_hash", product: "",
		sql: `ALTER TABLE agents ADD COLUMN IF NOT EXISTS api_key_hash BYTEA;
CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_api_key_hash ON agents (api_key_hash) WHERE api_key_hash IS NOT NULL;`,
	},
	// Central → agent command queue. Operator UI yazar (örn. "agent X'i
	// restart et"), agent long-poll'la çeker, HMAC doğrular, çalıştırır,
	// sonucu raporlar. Durability = queue Postgres'te; central restart
	// = no-op. Idempotency = state machine (pending → dispatched →
	// succeeded|failed|expired). UUIDv7 ID time-ordered, "since cursor"
	// pagination doğal.
	{
		name: "create_agent_commands", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS agent_commands (
    id            UUID PRIMARY KEY DEFAULT gen_uuidv7(),
    agent_id      TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,
    payload       JSONB NOT NULL DEFAULT '{}'::jsonb,
    state         TEXT NOT NULL DEFAULT 'pending'
                  CHECK (state IN ('pending','dispatched','succeeded','failed','expired')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    dispatched_at TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ NOT NULL,
    result        JSONB,
    issued_by     TEXT NOT NULL DEFAULT 'system',
    nonce         BYTEA NOT NULL,
    signature     BYTEA NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_commands_pending
    ON agent_commands (agent_id, id) WHERE state IN ('pending','dispatched');
CREATE INDEX IF NOT EXISTS idx_agent_commands_expires
    ON agent_commands (expires_at) WHERE state IN ('pending','dispatched');
CREATE INDEX IF NOT EXISTS idx_agent_commands_agent_recent
    ON agent_commands (agent_id, created_at DESC);`,
	},
	// Per-component retention budget for old release images. After a
	// successful promote the deployer prunes images from the local Docker
	// daemon that aren't (a) one of the last keep_releases succeeded
	// releases or (b) still bound to a warming/active/draining instance.
	// Default 3 = current + two previous, enough for rollback while
	// bounding disk growth.
	{
		name: "add_deploy_components_keep_releases", product: "muvon",
		sql: `ALTER TABLE deploy_components
              ADD COLUMN IF NOT EXISTS keep_releases INTEGER NOT NULL DEFAULT 3
              CHECK (keep_releases >= 1);`,
	},
	// Agent-reported public IP. last_remote_addr alone is unreliable for
	// DNS verification because in Hetzner-style private-network topologies
	// the source IP central sees is the agent's private interface, not
	// its public one. Agents now self-report their public IP at register
	// or heartbeat time (auto-detected by install-agent.sh or overridden
	// via --public-ip).
	{
		name: "add_agents_public_ip", product: "muvon",
		sql: `ALTER TABLE agents ADD COLUMN IF NOT EXISTS public_ip TEXT NOT NULL DEFAULT '';`,
	},
	// Host-level terminator binding. Until now hosts were implicitly
	// "everywhere": every agent and central pulled the same host set, and
	// whichever IP DNS pointed at decided where traffic terminated. That
	// hid two problems: (1) operators had no way to know which IP to put
	// in their DNS record at create time, and (2) misdirected traffic
	// (DNS pointed at the wrong machine) was silently accepted, including
	// ACME issuance attempts for a domain the receiving instance was not
	// supposed to terminate. target_kind+target_agent_id makes the choice
	// explicit: 'central' = MUVON itself, 'agent' + a specific agent_id =
	// that edge node. Config payload, proxy routing, and ACME HostPolicy
	// all key off this field to enforce ownership.
	{
		name: "add_hosts_target_terminator", product: "muvon",
		sql: `ALTER TABLE hosts
              ADD COLUMN IF NOT EXISTS target_kind TEXT NOT NULL DEFAULT 'central'
                  CHECK (target_kind IN ('central','agent'));
              ALTER TABLE hosts
              ADD COLUMN IF NOT EXISTS target_agent_id TEXT
                  REFERENCES agents(id) ON DELETE SET NULL;`,
	},
	// Operator-managed extra mount paths the edge agent should expose to
	// its embedded deployer (host bind, ro). Lets operators point a
	// managed component's env_file_path or mounts.source at any host
	// directory without SSH-editing the agent's compose file. Agent
	// receives this list via /api/v1/agent/config and threads it into
	// the helper container during agent.self_upgrade so compose is
	// rewritten + recreated with the new mounts.
	{
		name: "add_agents_extra_mounts", product: "muvon",
		sql: `ALTER TABLE agents ADD COLUMN IF NOT EXISTS extra_mounts TEXT[] NOT NULL DEFAULT '{}';`,
	},
	// Live container tail for agent host containers requires the
	// central to dial the agent's deployer gRPC over the private
	// network. host_id is what the agent reports to dialog as the
	// container_logs.host_id label — operator never sets it; the agent
	// stamps it on every auth'd request. deployer_addr is operator-set
	// in the UI (e.g. "10.0.0.3:9100"); empty disables the live-tail
	// routing for that agent.
	{
		name: "add_agents_host_id_deployer_addr", product: "muvon",
		sql: `ALTER TABLE agents
		      ADD COLUMN IF NOT EXISTS host_id TEXT NOT NULL DEFAULT '',
		      ADD COLUMN IF NOT EXISTS deployer_addr TEXT NOT NULL DEFAULT '';
		      CREATE INDEX IF NOT EXISTS agents_host_id_idx ON agents(host_id) WHERE host_id <> '';`,
	},
}
