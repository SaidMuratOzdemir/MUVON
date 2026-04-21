package db

import (
	"strings"
	"testing"
)

func TestMigrationsAvoidDestructiveDrops(t *testing.T) {
	for _, m := range migrations {
		if strings.Contains(strings.ToUpper(m.sql), "DROP TABLE IF EXISTS") {
			t.Fatalf("migration %q still contains DROP TABLE IF EXISTS", m.name)
		}
	}
}

func TestTLSCertificateMigrationSupportsIssuerScopedUpserts(t *testing.T) {
	var sql string
	for _, m := range migrations {
		if m.name == "create_tls_certificates" {
			sql = m.sql
			break
		}
	}
	if sql == "" {
		t.Fatal("create_tls_certificates migration not found")
	}
	if !strings.Contains(sql, "UNIQUE (domain, issuer)") {
		t.Fatal("create_tls_certificates must define a unique (domain, issuer) constraint")
	}
}

func TestHypertableMigrationsAreIdempotent(t *testing.T) {
	for _, name := range []string{
		"create_http_logs_hypertable",
		"create_http_log_bodies_hypertable",
		"create_waf_events_hypertable",
		"create_alerts_table",
	} {
		var sql string
		for _, m := range migrations {
			if m.name == name {
				sql = m.sql
				break
			}
		}
		if sql == "" {
			t.Fatalf("%s migration not found", name)
		}
		if !strings.Contains(sql, "if_not_exists => true") {
			t.Fatalf("%s must use create_hypertable(..., if_not_exists => true)", name)
		}
	}
}

func TestCentralSettingsLiveInMuvonSchema(t *testing.T) {
	productByName := map[string]string{}
	for _, m := range migrations {
		productByName[m.name] = m.product
	}

	if got := productByName["create_settings"]; got != "muvon" {
		t.Fatalf("create_settings product = %q, want muvon", got)
	}
	if got := productByName["seed_waf_settings"]; got != "muvon" {
		t.Fatalf("seed_waf_settings product = %q, want muvon", got)
	}
}

// TimescaleDB rejects ALTER TABLE ... ADD COLUMN ... DEFAULT now() on a
// compressed hypertable with SQLSTATE 0A000. The alerts table is a
// compressed hypertable; a previous version of this migration tripped
// that exact error in production. The fix is to add columns nullable,
// backfill, then enforce NOT NULL with a constant default if needed.
func TestAlertsGroupingMigrationAvoidsNonConstantDefault(t *testing.T) {
	var sql string
	for _, m := range migrations {
		if m.name == "add_alerts_grouping_columns" {
			sql = m.sql
			break
		}
	}
	if sql == "" {
		t.Fatal("add_alerts_grouping_columns migration missing")
	}
	if strings.Contains(sql, "DEFAULT now()") {
		t.Error("migration must not add columns with DEFAULT now() — alerts is a compressed hypertable")
	}
}

func TestAdminRefreshTokensMigrationShape(t *testing.T) {
	var sql string
	for _, m := range migrations {
		if m.name == "create_admin_refresh_tokens" {
			sql = m.sql
			break
		}
	}
	if sql == "" {
		t.Fatal("create_admin_refresh_tokens migration missing")
	}
	for _, must := range []string{
		"token_hash",
		"family_id",
		"parent_id",
		"revoked_at",
		"expires_at",
		"UNIQUE INDEX IF NOT EXISTS idx_admin_refresh_tokens_hash",
		"REFERENCES admin_users(id) ON DELETE CASCADE",
	} {
		if !strings.Contains(sql, must) {
			t.Errorf("admin_refresh_tokens missing required fragment: %q", must)
		}
	}
}
