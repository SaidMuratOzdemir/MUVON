package db

import (
	"context"
	"os"
	"testing"
	"time"
)

// What may be pruned is decided in SQL, and getting it wrong deletes an image
// something is still running on. The rules are worth pinning against a real
// planner rather than a mock: keep the last N succeeded releases, keep
// anything a live instance is bound to, and keep an image ID that a kept
// release resolves to even when this row's reference is different, because two
// references can point at one image.
//
// Skipped unless MUVON_TEST_PG_DSN names a throwaway database:
//
//	docker run -d --name muvon-prune-test -e POSTGRES_PASSWORD=test \
//	  -e POSTGRES_DB=muvon -e POSTGRES_USER=muvon -p 55432:5432 postgres:18-alpine
//	MUVON_TEST_PG_DSN='postgres://muvon:test@localhost:55432/muvon?sslmode=disable' \
//	  go test ./internal/db -run TestListPrunableImages -v
func TestListPrunableImages(t *testing.T) {
	dsn := os.Getenv("MUVON_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("MUVON_TEST_PG_DSN not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	database, err := New(ctx, dsn, "muvon")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer database.Close()

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := database.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("exec %q: %v", sql, err)
		}
	}

	exec(`DROP TABLE IF EXISTS deploy_instances, deploy_release_components, deploy_releases, deploy_components`)
	t.Cleanup(func() {
		_, _ = database.Pool.Exec(context.Background(),
			`DROP TABLE IF EXISTS deploy_instances, deploy_release_components, deploy_releases, deploy_components`)
	})

	exec(`CREATE TABLE deploy_components (id int primary key, agent_id text, slug text)`)
	exec(`CREATE TABLE deploy_releases (id uuid primary key, status text, created_at timestamptz)`)
	exec(`CREATE TABLE deploy_release_components (
	        release_uuid uuid, component_id int, image_ref text, image_id text NOT NULL DEFAULT '')`)
	exec(`CREATE TABLE deploy_instances (component_id int, release_uuid uuid, state text)`)

	exec(`INSERT INTO deploy_components VALUES (1, NULL, 'backend')`)
	rel := func(n int) string { return "00000000-0000-0000-0000-00000000000" + string(rune('0'+n)) }
	for i := 1; i <= 5; i++ {
		exec(`INSERT INTO deploy_releases VALUES ($1::uuid, 'succeeded', now() - make_interval(days => $2))`,
			rel(i), 6-i)
	}
	// v3 and the newest release v5 resolve to one image. v2 is what a draining
	// instance is still running.
	exec(`INSERT INTO deploy_release_components VALUES
	        ($1::uuid, 1, 'app:v1', 'sha256:aaa'),
	        ($2::uuid, 1, 'app:v2', 'sha256:bbb'),
	        ($3::uuid, 1, 'app:v3', 'sha256:ccc'),
	        ($4::uuid, 1, 'app:v4', 'sha256:ddd'),
	        ($5::uuid, 1, 'app:v5', 'sha256:ccc')`,
		rel(1), rel(2), rel(3), rel(4), rel(5))
	exec(`INSERT INTO deploy_instances VALUES (1, $1::uuid, 'draining')`, rel(2))

	got, err := database.ListPrunableImageRefs(ctx, 1, 2)
	if err != nil {
		t.Fatalf("list prunable: %v", err)
	}

	refs := map[string]bool{}
	for _, img := range got {
		refs[img.Ref] = true
	}
	if !refs["app:v1"] {
		t.Errorf("app:v1 is outside the keep window and unused, it should be prunable: %+v", got)
	}
	for _, ref := range []string{"app:v4", "app:v5"} {
		if refs[ref] {
			t.Errorf("%s is inside the keep window and must not be prunable", ref)
		}
	}
	if refs["app:v2"] {
		t.Error("app:v2 is bound to a draining instance and must not be prunable")
	}
	if refs["app:v3"] {
		t.Error("app:v3 resolves to the same image as the kept app:v5; pruning it would take the running image with it")
	}
}
