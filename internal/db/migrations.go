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
	product string // "muvon", "muwaf", "dialog", or "" for shared/all
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
    waf_enabled         BOOLEAN NOT NULL DEFAULT false,
    waf_exclude_paths   TEXT[] NOT NULL DEFAULT '{}',
    waf_detection_only  BOOLEAN NOT NULL DEFAULT false,
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
    waf_blocked       BOOLEAN NOT NULL DEFAULT false,
    waf_block_reason  TEXT,
    is_starred        BOOLEAN NOT NULL DEFAULT false,
    waf_score         INTEGER DEFAULT 0,
    waf_action        TEXT,
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
	// ── muWAF (WAF Engine) Tables ──
	{
		name: "create_waf_rules", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS waf_rules (
    id          SERIAL PRIMARY KEY,
    pattern     TEXT NOT NULL,
    is_regex    BOOLEAN NOT NULL DEFAULT false,
    category    TEXT NOT NULL CHECK (category IN (
        'xss','sqli','rce','lfi','rfi','ssrf','nosqli',
        'ssti','log4shell','prototype_pollution','session_fixation',
        'path_traversal','command_injection','custom'
    )),
    severity    INTEGER NOT NULL DEFAULT 5 CHECK (severity BETWEEN 1 AND 100),
    description TEXT,
    is_active   BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ DEFAULT now(),
    updated_at  TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_waf_rules_category ON waf_rules (category) WHERE is_active;`,
	},
	{
		name: "create_waf_ip_state", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS waf_ip_state (
    ip               TEXT PRIMARY KEY,
    status           TEXT NOT NULL DEFAULT 'clean',
    cumulative_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    last_seen        TIMESTAMPTZ NOT NULL DEFAULT now(),
    ban_until        TIMESTAMPTZ,
    ban_reason       TEXT,
    created_at       TIMESTAMPTZ DEFAULT now(),
    updated_at       TIMESTAMPTZ DEFAULT now()
);`,
	},
	{
		name: "create_waf_events_hypertable", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS waf_events (
    id              UUID DEFAULT gen_uuidv7() NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT now(),
    request_id      UUID,
    client_ip       TEXT NOT NULL,
    host            TEXT,
    method          TEXT,
    path            TEXT,
    request_score   INTEGER NOT NULL DEFAULT 0,
    ip_score        DOUBLE PRECISION NOT NULL DEFAULT 0,
    action          TEXT NOT NULL,
    matched_rules   JSONB,
    detection_mode  BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (id, timestamp)
);
SELECT create_hypertable('waf_events', by_range('timestamp', INTERVAL '1 day'), if_not_exists => true);
CREATE INDEX IF NOT EXISTS idx_waf_events_ip_ts ON waf_events (client_ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_waf_events_action ON waf_events (action, timestamp DESC);
SELECT add_retention_policy('waf_events', INTERVAL '30 days', if_not_exists => true);
ALTER TABLE waf_events SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'client_ip',
    timescaledb.compress_orderby = 'timestamp DESC'
);
SELECT add_compression_policy('waf_events', INTERVAL '7 days', if_not_exists => true);`,
	},
	{
		name: "create_waf_exclusions", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS waf_exclusions (
    id          SERIAL PRIMARY KEY,
    route_id    INTEGER,
    rule_id     INTEGER REFERENCES waf_rules(id) ON DELETE CASCADE,
    parameter   TEXT,
    location    TEXT CHECK (location IN ('path','query','header','body','all')),
    reason      TEXT,
    created_at  TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_waf_exclusions_route ON waf_exclusions (route_id);`,
	},
	{
		name: "create_waf_vt_cache", product: "muvon",
		sql: `
CREATE TABLE IF NOT EXISTS waf_vt_cache (
    ip              TEXT PRIMARY KEY,
    is_malicious    BOOLEAN NOT NULL DEFAULT false,
    malicious_count INTEGER DEFAULT 0,
    total_engines   INTEGER DEFAULT 0,
    reputation      INTEGER DEFAULT 0,
    checked_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);`,
	},
	// ── diaLOG: SIEM enrichment columns ──
	{
		name: "add_identity_geo_columns", product: "dialog",
		sql: `
ALTER TABLE http_logs ADD COLUMN IF NOT EXISTS user_identity JSONB;
ALTER TABLE http_logs ADD COLUMN IF NOT EXISTS country TEXT;
ALTER TABLE http_logs ADD COLUMN IF NOT EXISTS city TEXT;`,
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
    ('waf_url', '""'),
    ('waf_timeout_ms', '200'),
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
		name: "seed_waf_settings", product: "muvon",
		sql: `
INSERT INTO settings (key, value) VALUES
    ('waf_enabled_global', 'true'),
    ('waf_detection_only', 'false'),
    ('waf_score_threshold_log', '0'),
    ('waf_score_threshold_ratelimit', '11'),
    ('waf_score_threshold_block', '26'),
    ('waf_score_threshold_tempban', '51'),
    ('waf_score_threshold_ban', '101'),
    ('waf_ip_score_decay_per_hour', '5.0'),
    ('waf_ip_score_window_hours', '24'),
    ('waf_tempban_duration_minutes', '60'),
    ('waf_pattern_cache_ttl_seconds', '60'),
    ('waf_vt_api_key', '""'),
    ('waf_vt_timeout_seconds', '8'),
    ('waf_vt_cache_ttl_hours', '24'),
    ('waf_vt_score_contribution', '30'),
    ('waf_max_body_inspect_bytes', '65536'),
    ('waf_normalization_max_iterations', '3')
ON CONFLICT (key) DO NOTHING;`,
	},
	{
		name: "backfill_waf_settings_from_muwaf_schema", product: "muvon",
		sql: `
DO $$
BEGIN
    IF to_regclass('muwaf.settings') IS NULL THEN
        RETURN;
    END IF;

    INSERT INTO settings (key, value)
    SELECT key, value
    FROM muwaf.settings
    WHERE key IN (
        'waf_enabled_global',
        'waf_detection_only',
        'waf_score_threshold_log',
        'waf_score_threshold_ratelimit',
        'waf_score_threshold_block',
        'waf_score_threshold_tempban',
        'waf_score_threshold_ban',
        'waf_ip_score_decay_per_hour',
        'waf_ip_score_window_hours',
        'waf_tempban_duration_minutes',
        'waf_pattern_cache_ttl_seconds',
        'waf_vt_api_key',
        'waf_vt_timeout_seconds',
        'waf_vt_cache_ttl_hours',
        'waf_vt_score_contribution',
        'waf_max_body_inspect_bytes',
        'waf_normalization_max_iterations'
    )
    ON CONFLICT (key) DO NOTHING;
END $$;`,
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
	// ── Default WAF Rules ──
	{
		name: "seed_default_waf_rules", product: "muvon",
		sql: `
-- =============================================
-- Default WAF Rules — Seed Data
-- Severity guide: 1-10 low, 11-25 medium, 26-50 high, 51-100 critical
-- =============================================

-- === XSS (Cross-Site Scripting) ===
INSERT INTO waf_rules (pattern, is_regex, category, severity, description) VALUES
-- Substring patterns (Aho-Corasick)
('<script', false, 'xss', 30, 'HTML script tag'),
('javascript:', false, 'xss', 30, 'JavaScript URI scheme'),
('vbscript:', false, 'xss', 25, 'VBScript URI scheme'),
('onerror=', false, 'xss', 25, 'Event handler: onerror'),
('onload=', false, 'xss', 25, 'Event handler: onload'),
('onmouseover=', false, 'xss', 20, 'Event handler: onmouseover'),
('onfocus=', false, 'xss', 20, 'Event handler: onfocus'),
('onblur=', false, 'xss', 15, 'Event handler: onblur'),
('onclick=', false, 'xss', 20, 'Event handler: onclick'),
('onsubmit=', false, 'xss', 20, 'Event handler: onsubmit'),
('onchange=', false, 'xss', 15, 'Event handler: onchange'),
('oninput=', false, 'xss', 15, 'Event handler: oninput'),
('onkeyup=', false, 'xss', 15, 'Event handler: onkeyup'),
('onkeydown=', false, 'xss', 15, 'Event handler: onkeydown'),
('onmouseout=', false, 'xss', 15, 'Event handler: onmouseout'),
('ondragstart=', false, 'xss', 15, 'Event handler: ondragstart'),
('onanimationend=', false, 'xss', 15, 'Event handler: onanimationend'),
('ontransitionend=', false, 'xss', 15, 'Event handler: ontransitionend'),
('document.cookie', false, 'xss', 35, 'Cookie access attempt'),
('document.domain', false, 'xss', 30, 'DOM domain access'),
('document.write', false, 'xss', 30, 'DOM write'),
('document.location', false, 'xss', 25, 'DOM location access'),
('window.location', false, 'xss', 25, 'Window location access'),
('innerHTML', false, 'xss', 20, 'innerHTML manipulation'),
('outerHTML', false, 'xss', 20, 'outerHTML manipulation'),
('.fromCharCode', false, 'xss', 25, 'String.fromCharCode obfuscation'),
('eval(', false, 'xss', 35, 'JavaScript eval()'),
('setTimeout(', false, 'xss', 20, 'setTimeout execution'),
('setInterval(', false, 'xss', 20, 'setInterval execution'),
('expression(', false, 'xss', 25, 'CSS expression'),
('data:text/html', false, 'xss', 30, 'Data URI HTML'),
('data:application/x', false, 'xss', 25, 'Data URI application'),
('<iframe', false, 'xss', 25, 'Iframe injection'),
('<object', false, 'xss', 25, 'Object tag injection'),
('<embed', false, 'xss', 25, 'Embed tag injection'),
('<svg', false, 'xss', 20, 'SVG tag injection'),
('<math', false, 'xss', 15, 'MathML tag injection'),
('<img src', false, 'xss', 15, 'Image tag with src'),
('<body onload', false, 'xss', 30, 'Body onload event'),
('<input onfocus', false, 'xss', 25, 'Input onfocus event'),
('<details ontoggle', false, 'xss', 20, 'Details ontoggle event'),
('<marquee onstart', false, 'xss', 20, 'Marquee onstart event'),
('<!--', false, 'xss', 5, 'HTML comment (low severity, context-dependent)'),
-- Regex patterns
('<script[^>]*>[\s\S]*?</script>', true, 'xss', 40, 'Full script block'),
('on\w+\s*=\s*["\x27]', true, 'xss', 25, 'Generic event handler with value'),
('<\w+[^>]*\sstyle\s*=\s*["\x27][^"]*expression\s*\(', true, 'xss', 30, 'CSS expression in style attribute'),
('javascript\s*:\s*[\w.]+\s*\(', true, 'xss', 35, 'JavaScript URI with function call'),
('<svg[^>]*\son\w+\s*=', true, 'xss', 30, 'SVG with event handler'),
('<img[^>]*\sonerror\s*=', true, 'xss', 30, 'Image tag with onerror'),
('\\balert\s*\(', true, 'xss', 20, 'alert() call'),
('\\bprompt\s*\(', true, 'xss', 20, 'prompt() call'),
('\\bconfirm\s*\(', true, 'xss', 20, 'confirm() call'),
('\\batob\s*\(', true, 'xss', 20, 'atob() base64 decode'),
('\\bbtoa\s*\(', true, 'xss', 15, 'btoa() base64 encode'),
('\\bfetch\s*\(', true, 'xss', 20, 'fetch() API call'),
('new\s+Function\s*\(', true, 'xss', 35, 'Function constructor'),
('constructor\s*\[\s*["\x27]', true, 'xss', 30, 'Constructor bracket access'),
('\\bimport\s*\(', true, 'xss', 25, 'Dynamic import()'),
('<[^>]+\s+src\s*=\s*["\x27]?data:', true, 'xss', 30, 'Data URI in src attribute')
ON CONFLICT DO NOTHING;

-- === SQLi (SQL Injection) ===
INSERT INTO waf_rules (pattern, is_regex, category, severity, description) VALUES
-- Substring patterns
('union select', false, 'sqli', 35, 'UNION SELECT statement'),
('union all select', false, 'sqli', 35, 'UNION ALL SELECT'),
(' or 1=1', false, 'sqli', 30, 'Boolean tautology OR 1=1'),
(' and 1=1', false, 'sqli', 25, 'Boolean tautology AND 1=1'),
(' or 1=2', false, 'sqli', 25, 'Boolean contradiction test'),
(''' or ''=''', false, 'sqli', 30, 'String tautology'),
(''' or true--', false, 'sqli', 30, 'Boolean true with comment'),
('select * from', false, 'sqli', 30, 'SELECT * FROM'),
('drop table', false, 'sqli', 50, 'DROP TABLE attempt'),
('drop database', false, 'sqli', 50, 'DROP DATABASE attempt'),
('insert into', false, 'sqli', 30, 'INSERT INTO'),
('delete from', false, 'sqli', 35, 'DELETE FROM'),
('update set', false, 'sqli', 30, 'UPDATE SET'),
('information_schema', false, 'sqli', 40, 'Information schema access'),
('pg_catalog', false, 'sqli', 40, 'PostgreSQL catalog access'),
('pg_sleep', false, 'sqli', 35, 'PostgreSQL sleep (time-based blind)'),
('waitfor delay', false, 'sqli', 35, 'MSSQL WAITFOR DELAY (time-based blind)'),
('benchmark(', false, 'sqli', 35, 'MySQL BENCHMARK (time-based blind)'),
('sleep(', false, 'sqli', 30, 'MySQL SLEEP()'),
('load_file(', false, 'sqli', 40, 'MySQL LOAD_FILE()'),
('into outfile', false, 'sqli', 45, 'MySQL INTO OUTFILE'),
('into dumpfile', false, 'sqli', 45, 'MySQL INTO DUMPFILE'),
('group_concat(', false, 'sqli', 30, 'GROUP_CONCAT()'),
('concat(', false, 'sqli', 15, 'CONCAT()'),
('extractvalue(', false, 'sqli', 30, 'EXTRACTVALUE()'),
('updatexml(', false, 'sqli', 30, 'UPDATEXML()'),
('0x', false, 'sqli', 5, 'Hex literal (low, context-dependent)'),
('char(', false, 'sqli', 15, 'CHAR() function'),
('@@version', false, 'sqli', 35, 'Version variable access'),
('@@datadir', false, 'sqli', 35, 'Data directory variable'),
('sys.databases', false, 'sqli', 40, 'MSSQL sys.databases'),
('exec xp_', false, 'sqli', 45, 'MSSQL extended procedure'),
('exec sp_', false, 'sqli', 40, 'MSSQL stored procedure'),
('xp_cmdshell', false, 'sqli', 50, 'MSSQL xp_cmdshell'),
('xp_regread', false, 'sqli', 45, 'MSSQL registry read'),
('having 1=1', false, 'sqli', 30, 'HAVING tautology'),
('order by 1--', false, 'sqli', 25, 'ORDER BY column enumeration'),
-- Regex patterns
('union\s+(all\s+)?select\s', true, 'sqli', 40, 'UNION [ALL] SELECT with whitespace variants'),
('select\s+.+\s+from\s+', true, 'sqli', 30, 'Generic SELECT ... FROM'),
(';\s*(drop|alter|create|truncate|rename)\s', true, 'sqli', 45, 'Stacked query with DDL'),
(';\s*(insert|update|delete|exec)\s', true, 'sqli', 40, 'Stacked query with DML'),
('''\s*(or|and)\s+[''"\d].*=', true, 'sqli', 35, 'Quoted tautology/contradiction'),
('(''|")\s*;\s*--', true, 'sqli', 30, 'String termination with comment'),
('\b(select|insert|update|delete|drop|alter|create|exec)\b.*\b(from|into|set|table|where|values)\b', true, 'sqli', 25, 'SQL keyword combination'),
('/\*[\s\S]*?\*/', true, 'sqli', 15, 'SQL block comment (evasion technique)'),
('--\s*$', true, 'sqli', 10, 'SQL line comment at end'),
('#\s*$', true, 'sqli', 10, 'MySQL comment at end'),
('\bcase\s+when\b', true, 'sqli', 20, 'CASE WHEN conditional'),
('\bconvert\s*\(', true, 'sqli', 15, 'CONVERT function'),
('\bcast\s*\(', true, 'sqli', 15, 'CAST function'),
('\bif\s*\(.*,.*,', true, 'sqli', 25, 'IF() conditional function')
ON CONFLICT DO NOTHING;

-- === RCE (Remote Code Execution) ===
INSERT INTO waf_rules (pattern, is_regex, category, severity, description) VALUES
('system(', false, 'rce', 45, 'PHP system() call'),
('exec(', false, 'rce', 40, 'exec() call'),
('passthru(', false, 'rce', 45, 'PHP passthru()'),
('shell_exec(', false, 'rce', 45, 'PHP shell_exec()'),
('popen(', false, 'rce', 40, 'popen() call'),
('proc_open(', false, 'rce', 45, 'PHP proc_open()'),
('pcntl_exec(', false, 'rce', 45, 'PHP pcntl_exec()'),
('assert(', false, 'rce', 30, 'PHP assert()'),
('preg_replace', false, 'rce', 20, 'PHP preg_replace (potential /e modifier)'),
('create_function(', false, 'rce', 40, 'PHP create_function()'),
('call_user_func(', false, 'rce', 35, 'PHP call_user_func()'),
('call_user_func_array(', false, 'rce', 35, 'PHP call_user_func_array()'),
('${', false, 'rce', 20, 'Variable interpolation / template injection'),
('Runtime.getRuntime()', false, 'rce', 45, 'Java Runtime.getRuntime()'),
('ProcessBuilder', false, 'rce', 40, 'Java ProcessBuilder'),
('os.system(', false, 'rce', 45, 'Python os.system()'),
('subprocess.', false, 'rce', 40, 'Python subprocess module'),
('os.popen(', false, 'rce', 45, 'Python os.popen()'),
('__import__(', false, 'rce', 35, 'Python __import__()'),
('importlib', false, 'rce', 25, 'Python importlib'),
('child_process', false, 'rce', 40, 'Node.js child_process'),
('require(''child_process'')', false, 'rce', 45, 'Node.js require child_process'),
('spawn(', false, 'rce', 25, 'Process spawn'),
('execFile(', false, 'rce', 40, 'Node.js execFile()'),
-- Regex patterns
('(?:system|exec|passthru|shell_exec|popen)\s*\(', true, 'rce', 45, 'PHP execution function call'),
('(?:os\.(?:system|popen|exec)|subprocess\.(?:call|run|Popen))\s*\(', true, 'rce', 45, 'Python OS command execution'),
('Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec', true, 'rce', 50, 'Java Runtime exec chain'),
('(?:eval|Function)\s*\([^)]*(?:require|import|process)\b', true, 'rce', 45, 'Dynamic eval with module loading')
ON CONFLICT DO NOTHING;

-- === Command Injection ===
INSERT INTO waf_rules (pattern, is_regex, category, severity, description) VALUES
('; ls', false, 'command_injection', 35, 'Command chaining with ls'),
('| ls', false, 'command_injection', 35, 'Pipe to ls'),
('& ls', false, 'command_injection', 35, 'Background ls'),
('; cat ', false, 'command_injection', 40, 'Command chaining with cat'),
('| cat ', false, 'command_injection', 40, 'Pipe to cat'),
('; id', false, 'command_injection', 40, 'Command chaining with id'),
('| id', false, 'command_injection', 40, 'Pipe to id'),
('; whoami', false, 'command_injection', 40, 'Command chaining with whoami'),
('| whoami', false, 'command_injection', 40, 'Pipe to whoami'),
('; wget ', false, 'command_injection', 45, 'Command chaining with wget'),
('; curl ', false, 'command_injection', 45, 'Command chaining with curl'),
('| wget ', false, 'command_injection', 45, 'Pipe to wget'),
('| curl ', false, 'command_injection', 45, 'Pipe to curl'),
('; nc ', false, 'command_injection', 50, 'Netcat command'),
('| nc ', false, 'command_injection', 50, 'Pipe to netcat'),
('; rm ', false, 'command_injection', 50, 'Command chaining with rm'),
('; chmod ', false, 'command_injection', 45, 'Command chaining with chmod'),
('; chown ', false, 'command_injection', 45, 'Command chaining with chown'),
('/bin/sh', false, 'command_injection', 45, 'Shell path /bin/sh'),
('/bin/bash', false, 'command_injection', 45, 'Shell path /bin/bash'),
('/bin/zsh', false, 'command_injection', 40, 'Shell path /bin/zsh'),
('cmd.exe', false, 'command_injection', 45, 'Windows cmd.exe'),
('powershell', false, 'command_injection', 45, 'PowerShell reference'),
('$(', false, 'command_injection', 25, 'Command substitution $('),
-- Regex patterns
('[;&|]\s*(?:ls|cat|id|whoami|uname|pwd|wget|curl|nc|ncat|bash|sh|python|perl|ruby|php)\b', true, 'command_injection', 45, 'Command chaining/piping with common commands'),
('\$\((?:cat|ls|id|whoami|curl|wget|nc)', true, 'command_injection', 45, 'Command substitution with common commands'),
('\b(?:ping|traceroute|nslookup|dig)\s+-', true, 'command_injection', 30, 'Network diagnostic command with flags')
ON CONFLICT DO NOTHING;

-- === LFI (Local File Inclusion) / Path Traversal ===
INSERT INTO waf_rules (pattern, is_regex, category, severity, description) VALUES
('../', false, 'path_traversal', 20, 'Directory traversal ../'),
('..\\', false, 'path_traversal', 20, 'Directory traversal ..\\'),
('..../', false, 'path_traversal', 25, 'Double dot-dot traversal'),
('/etc/passwd', false, 'lfi', 40, 'Linux password file'),
('/etc/shadow', false, 'lfi', 50, 'Linux shadow file'),
('/etc/hosts', false, 'lfi', 30, 'Linux hosts file'),
('/etc/resolv.conf', false, 'lfi', 25, 'DNS resolver config'),
('/proc/self/', false, 'lfi', 40, 'Linux /proc/self access'),
('/proc/version', false, 'lfi', 30, 'Linux proc version'),
('/proc/net/tcp', false, 'lfi', 35, 'Linux proc network'),
('/var/log/', false, 'lfi', 35, 'Linux log files'),
('c:\\windows\\', false, 'lfi', 35, 'Windows system directory'),
('c:\\boot.ini', false, 'lfi', 40, 'Windows boot.ini'),
('c:\\inetpub\\', false, 'lfi', 35, 'IIS web root'),
('web.config', false, 'lfi', 30, 'ASP.NET config'),
('.htaccess', false, 'lfi', 30, 'Apache .htaccess'),
('.env', false, 'lfi', 35, '.env file access'),
('wp-config.php', false, 'lfi', 40, 'WordPress config'),
('config.php', false, 'lfi', 25, 'Generic config.php'),
('php://input', false, 'lfi', 40, 'PHP input wrapper'),
('php://filter', false, 'lfi', 40, 'PHP filter wrapper'),
('php://data', false, 'lfi', 35, 'PHP data wrapper'),
('expect://', false, 'lfi', 45, 'PHP expect wrapper'),
('file://', false, 'lfi', 35, 'File URI scheme'),
('zip://', false, 'lfi', 30, 'PHP zip wrapper'),
('phar://', false, 'lfi', 40, 'PHP phar wrapper'),
-- Regex patterns
('(?:\.\./){2,}', true, 'path_traversal', 30, 'Multiple directory traversal levels'),
('(?:%2e%2e[/\\\\]){2,}', true, 'path_traversal', 35, 'URL-encoded directory traversal'),
('(?:\.\.[\\/]){3,}(?:etc|var|proc|windows|boot)', true, 'lfi', 45, 'Deep traversal to sensitive directory'),
('(?:php|zlib|data|glob|phar|ssh2|rar|ogg|expect)://', true, 'lfi', 40, 'PHP stream wrapper'),
('/(?:etc/(?:passwd|shadow|group|gshadow|issue|hostname|crontab|apache2|nginx|mysql)|proc/(?:self|version|cmdline|cpuinfo|meminfo|net))', true, 'lfi', 45, 'Sensitive Linux file access')
ON CONFLICT DO NOTHING;

-- === SSRF (Server-Side Request Forgery) ===
INSERT INTO waf_rules (pattern, is_regex, category, severity, description) VALUES
('127.0.0.1', false, 'ssrf', 20, 'Localhost IPv4'),
('0.0.0.0', false, 'ssrf', 25, 'All interfaces IPv4'),
('localhost', false, 'ssrf', 15, 'Localhost hostname'),
('[::1]', false, 'ssrf', 20, 'Localhost IPv6'),
('169.254.169.254', false, 'ssrf', 45, 'AWS metadata endpoint'),
('metadata.google.internal', false, 'ssrf', 45, 'GCP metadata endpoint'),
('100.100.100.200', false, 'ssrf', 40, 'Alibaba Cloud metadata'),
('169.254.170.2', false, 'ssrf', 40, 'AWS ECS metadata'),
('fd00:ec2::254', false, 'ssrf', 40, 'AWS IMDSv2 IPv6'),
('instance/computeMetadata', false, 'ssrf', 45, 'GCP compute metadata path'),
('/latest/meta-data', false, 'ssrf', 45, 'AWS metadata path'),
('/latest/user-data', false, 'ssrf', 40, 'AWS user-data path'),
('/latest/api/token', false, 'ssrf', 40, 'AWS IMDSv2 token'),
('gopher://', false, 'ssrf', 40, 'Gopher protocol'),
('dict://', false, 'ssrf', 35, 'Dict protocol'),
('ftp://', false, 'ssrf', 20, 'FTP protocol'),
('tftp://', false, 'ssrf', 30, 'TFTP protocol'),
('ldap://', false, 'ssrf', 35, 'LDAP protocol'),
-- Regex patterns
('(?:^|[&?])(?:url|uri|path|src|dest|redirect|target|proxy|forward|next|link|fetch|load)\s*=\s*https?://(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)', true, 'ssrf', 40, 'SSRF via URL parameter to internal IP'),
('(?:0x7f|2130706433|017700000001|0177\.0\.0\.1)', true, 'ssrf', 40, 'Obfuscated localhost (hex/decimal/octal)')
ON CONFLICT DO NOTHING;

-- === RFI (Remote File Inclusion) ===
INSERT INTO waf_rules (pattern, is_regex, category, severity, description) VALUES
('=http://', false, 'rfi', 30, 'Parameter with HTTP URL'),
('=https://', false, 'rfi', 25, 'Parameter with HTTPS URL'),
('=ftp://', false, 'rfi', 30, 'Parameter with FTP URL'),
-- Regex patterns
('(?:include|require|include_once|require_once)\s*\(\s*["\x27]?https?://', true, 'rfi', 45, 'PHP remote file inclusion'),
('[?&]\w+=https?://[^&\s]+\.(?:php|asp|jsp|txt|pl|py)\b', true, 'rfi', 35, 'URL parameter pointing to remote script')
ON CONFLICT DO NOTHING;

-- === NoSQLi (NoSQL Injection) ===
INSERT INTO waf_rules (pattern, is_regex, category, severity, description) VALUES
('$gt', false, 'nosqli', 25, 'MongoDB $gt operator'),
('$lt', false, 'nosqli', 25, 'MongoDB $lt operator'),
('$ne', false, 'nosqli', 30, 'MongoDB $ne operator (auth bypass)'),
('$eq', false, 'nosqli', 15, 'MongoDB $eq operator'),
('$regex', false, 'nosqli', 30, 'MongoDB $regex operator'),
('$where', false, 'nosqli', 40, 'MongoDB $where (JS execution)'),
('$exists', false, 'nosqli', 20, 'MongoDB $exists operator'),
('$in', false, 'nosqli', 15, 'MongoDB $in operator'),
('$nin', false, 'nosqli', 20, 'MongoDB $nin operator'),
('$or', false, 'nosqli', 20, 'MongoDB $or operator'),
('$and', false, 'nosqli', 15, 'MongoDB $and operator'),
('$not', false, 'nosqli', 20, 'MongoDB $not operator'),
('$nor', false, 'nosqli', 20, 'MongoDB $nor operator'),
('db.collection', false, 'nosqli', 35, 'MongoDB collection access'),
('db.getCollection', false, 'nosqli', 35, 'MongoDB getCollection'),
('mapReduce', false, 'nosqli', 35, 'MongoDB mapReduce'),
('$lookup', false, 'nosqli', 25, 'MongoDB $lookup aggregation'),
-- Regex patterns
('\{\s*"\$(?:gt|lt|gte|lte|ne|eq|regex|where|exists|in|nin|or|and|not|nor|type|mod|all|elemMatch|size)"\s*:', true, 'nosqli', 35, 'MongoDB query operator in JSON'),
('\$where\s*:\s*["\x27]?function\s*\(', true, 'nosqli', 50, 'MongoDB $where with function')
ON CONFLICT DO NOTHING;

-- === SSTI (Server-Side Template Injection) ===
INSERT INTO waf_rules (pattern, is_regex, category, severity, description) VALUES
('{{', false, 'ssti', 15, 'Template expression open (Jinja2/Twig/Handlebars)'),
('${', false, 'ssti', 15, 'Template expression open (Freemarker/Thymeleaf)'),
('#{', false, 'ssti', 15, 'Template expression open (Pug/EL)'),
('<%', false, 'ssti', 15, 'Template expression open (ERB/JSP)'),
('__class__', false, 'ssti', 35, 'Python dunder class access'),
('__mro__', false, 'ssti', 40, 'Python MRO access'),
('__subclasses__', false, 'ssti', 45, 'Python subclasses traversal'),
('__globals__', false, 'ssti', 40, 'Python globals access'),
('__builtins__', false, 'ssti', 40, 'Python builtins access'),
('__import__', false, 'ssti', 40, 'Python import in template'),
('lipsum.__globals__', false, 'ssti', 45, 'Jinja2 lipsum globals exploit'),
('config.__class__', false, 'ssti', 45, 'Jinja2 config class exploit'),
('request.__class__', false, 'ssti', 40, 'Jinja2 request class exploit'),
('cycler.__init__', false, 'ssti', 40, 'Jinja2 cycler exploit'),
('joiner.__init__', false, 'ssti', 40, 'Jinja2 joiner exploit'),
('namespace.__init__', false, 'ssti', 40, 'Jinja2 namespace exploit'),
-- Regex patterns
('\{\{\s*[\d]+\s*[+\-*/]\s*[\d]+\s*\}\}', true, 'ssti', 25, 'Template arithmetic probe (e.g. {{7*7}})'),
('\{\{.*?__\w+__.*?\}\}', true, 'ssti', 40, 'Jinja2 dunder access in template'),
('\$\{.*?(?:getClass|Runtime|exec|ProcessBuilder).*?\}', true, 'ssti', 50, 'Java EL expression with execution'),
('#\{.*?(?:T\(|getClass|Runtime).*?\}', true, 'ssti', 50, 'SpEL expression with class access'),
('<#assign\s+\w+\s*=\s*"freemarker', true, 'ssti', 45, 'Freemarker assign directive'),
('\{\{\s*["\x27].*?["\x27]\s*\|\s*(?:safe|e|escape|raw)\s*\}\}', true, 'ssti', 20, 'Template filter usage')
ON CONFLICT DO NOTHING;

-- === Log4Shell ===
INSERT INTO waf_rules (pattern, is_regex, category, severity, description) VALUES
('${jndi:', false, 'log4shell', 50, 'Log4Shell JNDI lookup'),
('${jndi:ldap://', false, 'log4shell', 60, 'Log4Shell JNDI LDAP'),
('${jndi:rmi://', false, 'log4shell', 60, 'Log4Shell JNDI RMI'),
('${jndi:dns://', false, 'log4shell', 55, 'Log4Shell JNDI DNS'),
('${jndi:ldaps://', false, 'log4shell', 60, 'Log4Shell JNDI LDAPS'),
('${jndi:iiop://', false, 'log4shell', 55, 'Log4Shell JNDI IIOP'),
('${jndi:corba://', false, 'log4shell', 55, 'Log4Shell JNDI CORBA'),
('${jndi:nds://', false, 'log4shell', 55, 'Log4Shell JNDI NDS'),
('${lower:', false, 'log4shell', 35, 'Log4j lower lookup (obfuscation)'),
('${upper:', false, 'log4shell', 35, 'Log4j upper lookup (obfuscation)'),
('${env:', false, 'log4shell', 40, 'Log4j env lookup'),
('${sys:', false, 'log4shell', 35, 'Log4j sys lookup'),
('${date:', false, 'log4shell', 20, 'Log4j date lookup'),
('${::-j}', false, 'log4shell', 45, 'Log4Shell obfuscated jndi'),
-- Regex patterns
('\$\{(?:[a-z]+:)*j(?:[a-z]+:)*n(?:[a-z]+:)*d(?:[a-z]+:)*i\s*:', true, 'log4shell', 60, 'Log4Shell obfuscated JNDI (nested lookups)'),
('\$\{(?:lower|upper|[a-z]+)\s*:\s*\$\{', true, 'log4shell', 45, 'Log4j nested lookup (evasion)')
ON CONFLICT DO NOTHING;

-- === Prototype Pollution ===
INSERT INTO waf_rules (pattern, is_regex, category, severity, description) VALUES
('__proto__', false, 'prototype_pollution', 35, 'JavaScript __proto__ access'),
('constructor.prototype', false, 'prototype_pollution', 35, 'Constructor prototype access'),
('Object.assign', false, 'prototype_pollution', 15, 'Object.assign (context-dependent)'),
('Object.defineProperty', false, 'prototype_pollution', 20, 'Object.defineProperty'),
('[__proto__]', false, 'prototype_pollution', 35, 'Bracket __proto__ access'),
('["__proto__"]', false, 'prototype_pollution', 35, 'String bracket __proto__'),
-- Regex patterns
('(?:__proto__|constructor)\s*(?:\[|\.)\s*(?:prototype|__proto__|constructor)', true, 'prototype_pollution', 40, 'Chained prototype access'),
('(?:merge|extend|assign|defaults|clone|deepCopy)\s*\([^)]*__proto__', true, 'prototype_pollution', 40, 'Prototype pollution via merge/extend function')
ON CONFLICT DO NOTHING;

-- === Session Fixation ===
INSERT INTO waf_rules (pattern, is_regex, category, severity, description) VALUES
-- Regex patterns
('(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|ASPSESSIONID|session_id|sid|ssid|token)\s*=\s*[a-f0-9]{16,}', true, 'session_fixation', 30, 'Session ID in URL parameter'),
('Set-Cookie:\s*(?:PHPSESSID|JSESSIONID|session)', true, 'session_fixation', 35, 'Session cookie injection in header'),
('(?:document\.cookie|Set-Cookie)\s*=\s*["\x27]?\w*session', true, 'session_fixation', 35, 'Session cookie manipulation')
ON CONFLICT DO NOTHING;

-- === General Suspicious Patterns ===
INSERT INTO waf_rules (pattern, is_regex, category, severity, description) VALUES
('base64_decode(', false, 'custom', 15, 'PHP base64_decode()'),
('base64,', false, 'custom', 10, 'Base64 data marker'),
('phpinfo()', false, 'custom', 30, 'PHP info disclosure'),
('var_dump(', false, 'custom', 20, 'PHP var_dump()'),
('print_r(', false, 'custom', 15, 'PHP print_r()'),
('.git/', false, 'custom', 30, 'Git directory access'),
('.svn/', false, 'custom', 25, 'SVN directory access'),
('.DS_Store', false, 'custom', 20, 'macOS DS_Store file'),
('wp-admin', false, 'custom', 10, 'WordPress admin path'),
('wp-login', false, 'custom', 10, 'WordPress login path'),
('xmlrpc.php', false, 'custom', 20, 'WordPress XML-RPC'),
('/admin/config', false, 'custom', 15, 'Admin config path'),
('/debug/', false, 'custom', 20, 'Debug endpoint'),
('/actuator', false, 'custom', 25, 'Spring Boot actuator'),
('/console', false, 'custom', 20, 'Console endpoint'),
('/graphql', false, 'custom', 5, 'GraphQL endpoint probe'),
('/.well-known/', false, 'custom', 5, 'Well-known path probe'),
('/server-status', false, 'custom', 25, 'Apache server-status'),
('/server-info', false, 'custom', 25, 'Apache server-info'),
('/elmah.axd', false, 'custom', 30, 'ASP.NET ELMAH error log'),
('/trace.axd', false, 'custom', 30, 'ASP.NET trace'),
-- Scanner/bot detection
('sqlmap', false, 'custom', 40, 'SQLMap scanner signature'),
('nmap', false, 'custom', 30, 'Nmap scanner signature'),
('nikto', false, 'custom', 35, 'Nikto scanner signature'),
('dirbuster', false, 'custom', 35, 'DirBuster scanner signature'),
('gobuster', false, 'custom', 35, 'GoBuster scanner signature'),
('wpscan', false, 'custom', 35, 'WPScan scanner signature'),
('masscan', false, 'custom', 35, 'Masscan scanner signature'),
('nuclei', false, 'custom', 35, 'Nuclei scanner signature'),
('zgrab', false, 'custom', 30, 'ZGrab scanner signature'),
('burpsuite', false, 'custom', 25, 'Burp Suite signature'),
('acunetix', false, 'custom', 35, 'Acunetix scanner signature'),
('qualys', false, 'custom', 20, 'Qualys scanner signature'),
('nessus', false, 'custom', 25, 'Nessus scanner signature'),
('havij', false, 'custom', 40, 'Havij SQLi tool signature'),
-- Regex patterns
('(?:select|union|insert|update|delete|drop|alter|create|exec|having|order\s+by|group\s+by)\s', true, 'custom', 10, 'Common SQL keyword (very low severity, context indicator)')
ON CONFLICT DO NOTHING;
`,
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
}
