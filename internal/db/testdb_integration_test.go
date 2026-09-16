package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// openTestDatabase creates a database for one test on the server named by
// MUVON_TEST_PG_DSN, with the given extensions, and drops it when the test
// ends. It returns the DSN; the caller opens it with New and the search path it
// needs. Tests in this package cannot use internal/testpg, which imports this
// package.
//
// A database per test is what makes these tests repeatable: a test that shapes
// a shared database leaves state the next run trips over. Each test names only
// the extensions it uses, so one that needs TimescaleDB alone still runs on a
// plain TimescaleDB server, as CI's integration job provides.
func openTestDatabase(t *testing.T, extensions ...string) string {
	t.Helper()
	adminDSN := os.Getenv("MUVON_TEST_PG_DSN")
	if adminDSN == "" {
		t.Skip("MUVON_TEST_PG_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer admin.Close(ctx)

	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("random: %v", err)
	}
	name := "muvon_dbtest_" + hex.EncodeToString(suffix)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		c, err := pgx.Connect(cctx, adminDSN)
		if err != nil {
			t.Logf("drop %s: connect: %v", name, err)
			return
		}
		defer c.Close(cctx)
		if _, err := c.Exec(cctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Logf("drop %s: %v", name, err)
		}
	})

	u, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.Path = "/" + name
	dsn := u.String()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect %s: %v", name, err)
	}
	defer conn.Close(ctx)
	for _, ext := range extensions {
		if _, err := conn.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS "+ext); err != nil {
			t.Fatalf("extension %s: %v", ext, err)
		}
	}
	return dsn
}
