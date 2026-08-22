package grpcserver

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeBackup(t *testing.T, dir, name string, age time.Duration) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatalf("chtimes %s: %v", name, err)
	}
	return path
}

// A .part is an attempt still in flight and a .rejected is the evidence of a
// failed verification. Offering either as a backup, or pruning them away,
// would both be wrong: one is not a backup yet, the other is the record of
// what went wrong.
func TestBackupFilesOnlyListsPublishedDumps(t *testing.T) {
	dir := t.TempDir()
	writeBackup(t, dir, "pgdata-20260101-000000.dump", 3*time.Hour)
	writeBackup(t, dir, "pgdata-20260102-000000.dump", 1*time.Hour)
	writeBackup(t, dir, "pgdata-20260103-000000.dump.part", time.Minute)
	writeBackup(t, dir, "pgdata-20260103-000000.dump.rejected", time.Minute)
	writeBackup(t, dir, "notes.txt", time.Minute)

	files, err := backupFiles(dir)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(files) != 2 {
		names := []string{}
		for _, f := range files {
			names = append(names, f.name)
		}
		t.Fatalf("expected 2 published dumps, got %v", names)
	}
	// Newest first, so the panel and the prune agree on what "recent" means.
	if files[0].name != "pgdata-20260102-000000.dump" {
		t.Fatalf("not sorted newest first: %s came first", files[0].name)
	}
}

func TestBackupFilesMissingDirectory(t *testing.T) {
	files, err := backupFiles(filepath.Join(t.TempDir(), "absent"))
	if err != nil {
		t.Fatalf("a missing backup directory is not an error before the first backup: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected nothing, got %d", len(files))
	}
}

func TestPruneKeepsNewestAndSparesOtherFiles(t *testing.T) {
	dir := t.TempDir()
	for i := 1; i <= 8; i++ {
		writeBackup(t, dir, "pgdata-2026010"+string(rune('0'+i))+"-000000.dump", time.Duration(9-i)*time.Hour)
	}
	rejected := writeBackup(t, dir, "pgdata-20260109-000000.dump.rejected", time.Minute)
	part := writeBackup(t, dir, "pgdata-20260109-000000.dump.part", time.Minute)

	removed := pruneBackups(dir, 5)
	if len(removed) != 3 {
		t.Fatalf("expected 3 removals from 8 dumps keeping 5, got %v", removed)
	}
	left, _ := backupFiles(dir)
	if len(left) != 5 {
		t.Fatalf("expected 5 dumps left, got %d", len(left))
	}
	// The three oldest went, not three arbitrary ones.
	for _, f := range left {
		for _, r := range removed {
			if f.name == r {
				t.Fatalf("%s was reported removed but is still listed", r)
			}
		}
	}
	for _, p := range []string{rejected, part} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("prune deleted %s, which is not a published backup", filepath.Base(p))
		}
	}
}

func TestPruneDoesNothingUnderTheLimit(t *testing.T) {
	dir := t.TempDir()
	writeBackup(t, dir, "pgdata-20260101-000000.dump", time.Hour)
	if removed := pruneBackups(dir, 5); len(removed) != 0 {
		t.Fatalf("nothing should be pruned below the limit, removed %v", removed)
	}
	if removed := pruneBackups(dir, 0); len(removed) != 0 {
		t.Fatalf("a zero limit must be treated as no pruning, not as delete-everything, removed %v", removed)
	}
	if left, _ := backupFiles(dir); len(left) != 1 {
		t.Fatal("the only backup was deleted")
	}
}
