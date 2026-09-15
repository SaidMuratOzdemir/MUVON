// Package testpg gives integration tests a real, fully migrated database.
//
// Tests that depend on PostgreSQL behaviour (a COPY inside a transaction, a
// partial unique index, TimescaleDB) cannot be trusted against a fake, so they
// run here against a throwaway database created per test from the server named
// by MUVON_TEST_PG_DSN. The server needs the extensions the product image
// ships: TimescaleDB, pg_uuidv7 and pg_trgm.
//
//	docker build -t muvon-postgres-test:local ./postgres
//	docker run -d --name muvon-test-pg -e POSTGRES_PASSWORD=test \
//	  -e POSTGRES_USER=muvon -e POSTGRES_DB=muvon -p 55432:5432 \
//	  muvon-postgres-test:local postgres \
//	  -c shared_preload_libraries=timescaledb,pg_cron,pg_search
//	MUVON_TEST_PG_DSN='postgres://muvon:test@localhost:55432/muvon?sslmode=disable' go test ./...
package testpg

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"muvon/internal/db"
)

// DBs holds one handle per product, each with the search_path its binary uses.
type DBs struct {
	Muvon  *db.DB
	Dialog *db.DB
	DSN    string
}

// Open skips the test unless MUVON_TEST_PG_DSN is set, and otherwise returns a
// new database with every migration applied. The database is dropped when the
// test ends.
func Open(t testing.TB) DBs {
	t.Helper()
	adminDSN := os.Getenv("MUVON_TEST_PG_DSN")
	if adminDSN == "" {
		t.Skip("MUVON_TEST_PG_DSN not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("testpg: connect: %v", err)
	}
	defer admin.Close(ctx)

	name := "muvon_test_" + randomSuffix(t)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("testpg: create database: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		conn, err := pgx.Connect(cctx, adminDSN)
		if err != nil {
			t.Logf("testpg: cleanup connect: %v", err)
			return
		}
		defer conn.Close(cctx)
		if _, err := conn.Exec(cctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Logf("testpg: drop %s: %v", name, err)
		}
	})

	dsn := withDatabase(t, adminDSN, name)

	// The product creates its extensions at database init, before any service
	// connects, so they land in public. Mirror postgres/init.sql.
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("testpg: connect to %s: %v", name, err)
	}
	for _, ext := range []string{
		"CREATE EXTENSION IF NOT EXISTS pg_uuidv7",
		"CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE",
		"CREATE EXTENSION IF NOT EXISTS pg_trgm",
	} {
		if _, err := conn.Exec(ctx, ext); err != nil {
			conn.Close(ctx)
			t.Fatalf("testpg: %s: %v", ext, err)
		}
	}
	conn.Close(ctx)

	// dialog first, as compose starts it: muvon depends on dialog-siem, and
	// the shared drop_pg_search would otherwise remove the extension before
	// dialog's early BM25 migration runs.
	dialogDB, err := db.New(ctx, dsn, "dialog", "muvon")
	if err != nil {
		t.Fatalf("testpg: open dialog: %v", err)
	}
	t.Cleanup(dialogDB.Close)
	if err := dialogDB.RunMigrations(ctx); err != nil {
		t.Fatalf("testpg: dialog migrations: %v", err)
	}

	muvonDB, err := db.New(ctx, dsn, "muvon")
	if err != nil {
		t.Fatalf("testpg: open muvon: %v", err)
	}
	t.Cleanup(muvonDB.Close)
	if err := muvonDB.RunMigrations(ctx); err != nil {
		t.Fatalf("testpg: muvon migrations: %v", err)
	}

	return DBs{Muvon: muvonDB, Dialog: dialogDB, DSN: dsn}
}

func withDatabase(t testing.TB, dsn, name string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("testpg: parse dsn: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

func randomSuffix(t testing.TB) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("testpg: random: %v", err)
	}
	return hex.EncodeToString(b)
}
