package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"muvon/internal/db"
	"muvon/internal/testpg"
)

// Four releases, oldest first: r1 and r2 succeeded, r3 failed, r4 succeeded.
func seedReleases(t *testing.T, d *db.DB) {
	t.Helper()
	if _, err := d.Pool.Exec(context.Background(), `
		INSERT INTO muvon.deploy_projects (slug, name) VALUES ('shop', 'Shop');
		INSERT INTO muvon.deploy_components (project_id, slug, name, image_repo, internal_port)
		SELECT id, 'web', 'Web', 'registry.example.com/shop', 8000 FROM muvon.deploy_projects WHERE slug = 'shop';
		INSERT INTO muvon.deploy_releases (project_id, release_id, status, created_at)
		SELECT p.id, v.release_id, v.status, now() - v.age
		FROM muvon.deploy_projects p,
		     (VALUES ('r1', 'succeeded', interval '4 hours'),
		             ('r2', 'succeeded', interval '3 hours'),
		             ('r3', 'failed',    interval '2 hours'),
		             ('r4', 'succeeded', interval '1 hour')) AS v(release_id, status, age)
		WHERE p.slug = 'shop';
		INSERT INTO muvon.deploy_release_components (release_uuid, component_id, image_ref)
		SELECT r.id, c.id, 'registry.example.com/shop:' || r.release_id
		FROM muvon.deploy_releases r JOIN muvon.deploy_components c ON c.slug = 'web';`); err != nil {
		t.Fatalf("seed releases: %v", err)
	}
}

func TestRollbackTargetNeverLiesAhead(t *testing.T) {
	dbs := testpg.Open(t)
	seedReleases(t, dbs.Muvon)
	ctx := context.Background()

	for _, tc := range []struct {
		from, want string
		err        error
	}{
		{from: "", want: "r2"},
		{from: "r4", want: "r2"},
		{from: "r3", want: "r2"},
		{from: "r2", want: "r1"},
		{from: "r1", err: db.ErrNoEarlierRelease},
		{from: "missing", err: db.ErrReleaseNotFound},
	} {
		got, err := dbs.Muvon.PreviousSucceededRelease(ctx, "shop", tc.from)
		if tc.err != nil {
			if !errors.Is(err, tc.err) {
				t.Errorf("from %q: err = %v, want %v", tc.from, err, tc.err)
			}
			continue
		}
		if err != nil || got.ReleaseID != tc.want {
			t.Errorf("from %q: target = %q (%v), want %q", tc.from, got.ReleaseID, err, tc.want)
			continue
		}
		if len(got.Components) != 1 || got.Components[0].ImageRef != "registry.example.com/shop:"+tc.want {
			t.Errorf("from %q: components = %+v, want the %s image", tc.from, got.Components, tc.want)
		}
	}

	for _, tc := range []struct {
		to, want string
		err      error
	}{
		{to: "r1", want: "r1"},
		{to: "r3", err: db.ErrReleaseNotSucceeded},
		{to: "missing", err: db.ErrReleaseNotFound},
	} {
		got, err := dbs.Muvon.SucceededRelease(ctx, "shop", tc.to)
		if tc.err != nil {
			if !errors.Is(err, tc.err) {
				t.Errorf("to %q: err = %v, want %v", tc.to, err, tc.err)
			}
			continue
		}
		if err != nil || got.ReleaseID != tc.want {
			t.Errorf("to %q: target = %q (%v), want %q", tc.to, got.ReleaseID, err, tc.want)
		}
	}
}

func TestRollbackEndpoint(t *testing.T) {
	dbs := testpg.Open(t)
	seedReleases(t, dbs.Muvon)
	srv := &Server{db: dbs.Muvon}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/deploy/projects/{slug}/rollback", srv.handleRollbackProject)

	call := func(body map[string]string) (int, map[string]any) {
		t.Helper()
		b, _ := json.Marshal(body)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("POST", "/api/deploy/projects/shop/rollback", bytes.NewReader(b)))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	for _, tc := range []struct {
		name string
		body map[string]string
		code int
	}{
		{"both named", map[string]string{"from_release_id": "r4", "to_release_id": "r1"}, http.StatusBadRequest},
		{"target failed", map[string]string{"to_release_id": "r3"}, http.StatusConflict},
		{"target missing", map[string]string{"to_release_id": "missing"}, http.StatusNotFound},
		{"nothing earlier", map[string]string{"from_release_id": "r1"}, http.StatusNotFound},
	} {
		if code, out := call(tc.body); code != tc.code {
			t.Errorf("%s: status = %d %v, want %d", tc.name, code, out, tc.code)
		}
	}

	code, out := call(map[string]string{"to_release_id": "r1"})
	if code != http.StatusAccepted || out["rolled_to"] != "r1" {
		t.Fatalf("rollback to r1 = %d %v, want 202 rolled_to r1", code, out)
	}
}
