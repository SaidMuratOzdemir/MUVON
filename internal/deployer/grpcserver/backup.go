package grpcserver

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	pb "muvon/proto/deployerpb"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// backupKeep is how many dumps survive a new one. The installer keeps the same
// number for its shell-side backups. Without a limit the directory only grows:
// this deployment reached 5.5 GB of them before anyone looked.
const backupKeep = 5

// CreateBackup takes a verified pg_dump on demand.
//
// Until now the only way to get a backup was to start a system upgrade, which
// meant no upgrade, no backup — exactly backwards for something you want
// before risky work rather than as a side effect of it. The dump itself goes
// through the same path the upgrade uses: byte-exact streaming to a .part
// file, a custom-format header check, and pg_restore -l against the database's
// own image before the file is published.
func (s *Server) CreateBackup(ctx context.Context, _ *pb.CreateBackupRequest) (*pb.CreateBackupResponse, error) {
	// Shared with SystemUpgrade: both dump the same database into the same
	// directory, and running them at once would compete for IO on a live
	// system for no benefit.
	if !upgradeMu.TryLock() {
		return nil, status.Error(codes.Aborted, "another upgrade or backup is already running")
	}
	defer upgradeMu.Unlock()

	// The verification steps report through the same emit signature the
	// upgrade stream uses. Here there is no stream, so warnings are collected
	// and handed back: a backup whose verification was skipped must say so
	// rather than looking identical to a verified one.
	var notes []string
	verified := true
	emit := func(step, level, msg string, _ bool) {
		switch level {
		case "warn", "error":
			verified = false
			notes = append(notes, msg)
			slog.Warn("backup", "step", step, "message", msg)
		default:
			slog.Info("backup", "step", step, "message", msg)
		}
	}

	path, err := s.runPGDump(ctx, emit)
	if err != nil {
		slog.Error("manual backup failed", "error", err)
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	var size int64
	created := time.Now().UTC()
	if info, statErr := os.Stat(path); statErr == nil {
		size = info.Size()
		created = info.ModTime().UTC()
	}

	if removed := pruneBackups(backupDir, backupKeep); len(removed) > 0 {
		slog.Info("older backups pruned", "kept", backupKeep, "removed", removed)
		notes = append(notes, fmt.Sprintf("%d eski yedek silindi (son %d tutuluyor)", len(removed), backupKeep))
	}

	slog.Info("manual backup written", "path", path, "bytes", size, "verified", verified)
	return &pb.CreateBackupResponse{
		Path:      path,
		Bytes:     size,
		CreatedAt: created.Format(time.RFC3339),
		Verified:  verified,
		Note:      strings.Join(notes, " · "),
	}, nil
}

// ListBackups reports the dumps on disk, newest first.
func (s *Server) ListBackups(_ context.Context, _ *pb.ListBackupsRequest) (*pb.ListBackupsResponse, error) {
	files, err := backupFiles(backupDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "listing backups: %v", err)
	}
	resp := &pb.ListBackupsResponse{KeepLimit: backupKeep}
	for _, f := range files {
		resp.Backups = append(resp.Backups, &pb.BackupInfo{
			Name:      f.Name(),
			Bytes:     f.size,
			CreatedAt: f.modTime.UTC().Format(time.RFC3339),
		})
	}
	return resp, nil
}

// backupFile is one dump on disk, newest first when sorted.
type backupFile struct {
	name    string
	size    int64
	modTime time.Time
}

func (f backupFile) Name() string { return f.name }

// backupFiles lists published dumps, newest first. Only pgdata-*.dump counts:
// a .part is an attempt in flight and a .rejected is evidence of a failed
// verification, and neither is a backup anyone should be offered.
func backupFiles(dir string) ([]backupFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []backupFile
	for _, e := range entries {
		if e.IsDir() || !isPublishedBackup(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, backupFile{name: e.Name(), size: info.Size(), modTime: info.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].modTime.After(out[j].modTime) })
	return out, nil
}

func isPublishedBackup(name string) bool {
	return strings.HasPrefix(name, "pgdata-") && strings.HasSuffix(name, ".dump")
}

// pruneBackups deletes everything past the newest keep dumps and returns what
// it removed. Rejected and in-flight files are left alone deliberately.
func pruneBackups(dir string, keep int) []string {
	if keep <= 0 {
		return nil
	}
	files, err := backupFiles(dir)
	if err != nil || len(files) <= keep {
		return nil
	}
	var removed []string
	for _, f := range files[keep:] {
		if err := os.Remove(filepath.Join(dir, f.name)); err != nil {
			slog.Warn("pruning backup failed", "file", f.name, "error", err)
			continue
		}
		removed = append(removed, f.name)
	}
	return removed
}
