package deployer

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// End-to-end proof that a dump taken through ContainerExecStream restores.
// The frame tests cover the decoding; this one covers the whole path against a
// real daemon and a real postgres, which is the only way to be sure the fix
// keeps a pg_dump restorable: the log demuxer would strip its newlines.
//
// Skipped unless MUVON_TEST_PG_CONTAINER names a running postgres container
// whose image also carries pg_restore:
//
//	docker run -d --name muvon-dump-test -e POSTGRES_PASSWORD=test \
//	  -e POSTGRES_DB=muvon -e POSTGRES_USER=muvon postgres:18-alpine
//	MUVON_TEST_PG_CONTAINER=muvon-dump-test \
//	  go test ./internal/deployer -run TestContainerExecStreamProducesRestorableDump -v
func TestContainerExecStreamProducesRestorableDump(t *testing.T) {
	container := os.Getenv("MUVON_TEST_PG_CONTAINER")
	if container == "" {
		t.Skip("MUVON_TEST_PG_CONTAINER not set")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI not on PATH")
	}

	client, err := NewDockerClient(os.Getenv("DOCKER_HOST"))
	if err != nil {
		t.Fatalf("docker client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Give the dump something with structure to carry.
	seed := []string{"psql", "-U", "muvon", "-d", "muvon", "-c",
		"CREATE TABLE IF NOT EXISTS demo (id int primary key, note text); " +
			"INSERT INTO demo VALUES (1, 'line one'), (2, 'line two') ON CONFLICT DO NOTHING;"}
	if out, code, err := client.ContainerExecCaptureCode(ctx, container, seed); err != nil || code != 0 {
		t.Fatalf("seed failed: code=%d err=%v out=%s", code, err, out)
	}

	path := filepath.Join(t.TempDir(), "e2e.dump")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	code, stderrTail, err := client.ContainerExecStream(ctx, container,
		[]string{"pg_dump", "-Fc", "-U", "muvon", "-d", "muvon"}, f)
	if cerr := f.Close(); cerr != nil {
		t.Fatalf("close: %v", cerr)
	}
	if err != nil {
		t.Fatalf("exec stream: %v (stderr: %s)", err, stderrTail)
	}
	if code != 0 {
		t.Fatalf("pg_dump exited %d: %s", code, stderrTail)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read dump: %v", err)
	}
	if !bytes.HasPrefix(body, []byte("PGDMP")) {
		t.Fatalf("dump does not start with PGDMP: %q", body[:min(16, len(body))])
	}
	// The corruption signature: a compressed archive of any size always
	// carries newline bytes. Zero of them means something stripped them, which
	// is exactly what every archive on the affected host looked like.
	if n := bytes.Count(body, []byte{'\n'}); n == 0 {
		t.Fatalf("dump of %d bytes contains no 0x0A byte at all", len(body))
	}

	// Verify with the database's own pg_restore: a host copy is routinely an
	// older major version and would reject a newer archive for reasons that
	// have nothing to do with this code.
	if out, err := exec.CommandContext(ctx, "docker", "cp", path, container+":/tmp/e2e.dump").CombinedOutput(); err != nil {
		t.Fatalf("docker cp failed: %v\n%s", err, out)
	}
	toc, code, err := client.ContainerExecCaptureCode(ctx, container,
		[]string{"pg_restore", "-l", "/tmp/e2e.dump"})
	if err != nil {
		t.Fatalf("pg_restore exec failed: %v", err)
	}
	if code != 0 {
		t.Fatalf("pg_restore -l rejected the dump (exit %d):\n%s", code, toc)
	}
	if !bytes.Contains(toc, []byte("demo")) {
		t.Fatalf("restored table of contents does not mention the seeded table:\n%s", toc)
	}

	// Reproduce the original defect against the same real archive, so the
	// diagnosis is demonstrated rather than assumed: routed through the
	// line-oriented path, the identical command yields a shorter file with no
	// newline bytes left in it, which is exactly what the affected host's
	// backups looked like.
	viaLines, _, err := client.execAttached(ctx, container,
		[]string{"pg_dump", "-Fc", "-U", "muvon", "-d", "muvon"})
	if err != nil {
		t.Fatalf("line-path exec failed: %v", err)
	}
	if bytes.Equal(viaLines.Bytes(), body) {
		t.Fatal("line path reproduced the archive byte for byte; the two paths are no longer distinct")
	}

	linePath := filepath.Join(t.TempDir(), "vialines.dump")
	if err := os.WriteFile(linePath, viaLines.Bytes(), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if out, err := exec.CommandContext(ctx, "docker", "cp", linePath, container+":/tmp/vialines.dump").CombinedOutput(); err != nil {
		t.Fatalf("docker cp failed: %v\n%s", err, out)
	}
	lineTOC, lineCode, err := client.ContainerExecCaptureCode(ctx, container,
		[]string{"pg_restore", "-l", "/tmp/vialines.dump"})
	if err != nil {
		t.Fatalf("pg_restore exec failed: %v", err)
	}
	if lineCode == 0 {
		t.Fatalf("the line path still produced a restorable archive, so it no longer reproduces the defect:\n%s", lineTOC)
	}
	t.Logf("stream path: %d bytes, %d newlines, pg_restore ok; line path: %d bytes, pg_restore exit %d",
		len(body), bytes.Count(body, []byte{'\n'}), viaLines.Len(), lineCode)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
