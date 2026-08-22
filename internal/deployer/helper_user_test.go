package deployer

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeDocker stands in for the daemon so the create request can be inspected.
// It answers the four calls RunHelperContainer makes and records the body of
// the create call.
func fakeDocker(t *testing.T, captured *map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/containers/create"):
			body, _ := io.ReadAll(r.Body)
			var parsed map[string]any
			if err := json.Unmarshal(body, &parsed); err != nil {
				t.Errorf("create body is not JSON: %v", err)
			}
			*captured = parsed
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Id":"helper123"}`))
		case strings.HasSuffix(r.URL.Path, "/logs"):
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/start"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/wait"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"StatusCode":0}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
}

// The backup verifier reads a file the deployer wrote as root 0600. Official
// images run as an unprivileged user, so without an explicit override
// pg_restore fails with EACCES and a perfectly good archive is reported as
// corrupt — which aborted a real upgrade. This pins the override reaching the
// daemon.
func TestRunHelperContainerPassesUser(t *testing.T) {
	var captured map[string]any
	srv := fakeDocker(t, &captured)
	defer srv.Close()

	c, err := NewDockerClient(strings.Replace(srv.URL, "http://", "tcp://", 1))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	_, logs, wait, err := c.RunHelperContainer(context.Background(), HelperContainerOpts{
		Image: "postgres:18",
		Cmd:   []string{"pg_restore", "-l", "/verify/x.dump"},
		Binds: []string{"muvon_backups:/verify:ro"},
		User:  "root",
	})
	if err != nil {
		t.Fatalf("run helper: %v", err)
	}
	if logs != nil {
		logs.Close()
	}
	if wait != nil {
		_, _ = wait()
	}

	if got := captured["User"]; got != "root" {
		t.Fatalf("create request User = %v, want root", got)
	}
	hostCfg, _ := captured["HostConfig"].(map[string]any)
	binds, _ := hostCfg["Binds"].([]any)
	if len(binds) != 1 || binds[0] != "muvon_backups:/verify:ro" {
		t.Fatalf("verifier mount is not read-only: %v", binds)
	}
}

// A helper that does not ask for a user must not get one, so nothing else
// silently starts running as root.
func TestRunHelperContainerOmitsUserByDefault(t *testing.T) {
	var captured map[string]any
	srv := fakeDocker(t, &captured)
	defer srv.Close()

	c, err := NewDockerClient(strings.Replace(srv.URL, "http://", "tcp://", 1))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	_, logs, wait, err := c.RunHelperContainer(context.Background(), HelperContainerOpts{
		Image: "docker:27-cli",
		Cmd:   []string{"sh", "-c", "true"},
	})
	if err != nil {
		t.Fatalf("run helper: %v", err)
	}
	if logs != nil {
		logs.Close()
	}
	if wait != nil {
		_, _ = wait()
	}

	if _, present := captured["User"]; present {
		t.Fatalf("User was sent for a helper that did not ask for one: %v", captured["User"])
	}
}
