package grpcserver

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"muvon/internal/deployer"
	pb "muvon/proto/deployerpb"
)

// SystemUpgrade orchestrates a pull-and-recreate of the central MUVON
// stack. Steps are emitted as gRPC stream events; the admin handler
// proxies them straight to SSE. Sequence:
//
//   1. Acquire the in-process upgrade lock — two operators cannot race.
//   2. Write target tag to /host/muvon/.env (VERSION=<tag>).
//   3. pg_dump -Fc (optional) → /var/lib/muvon/backups/<timestamp>.dump
//   4. Spawn a "muvon-upgrader" helper container (docker:cli image)
//      with /var/run/docker.sock + /host/muvon RW mounted, running
//      `docker compose pull && docker compose up -d --wait`. We pipe
//      its stdout/stderr line-by-line back into the stream so the UI
//      sees real progress, not a black box.
//   5. After the helper exits successfully, the helper itself will have
//      recreated this very container (muvon-deployer) from a fresh
//      image — meaning the stream is closed mid-flight by Docker. The
//      UI handles that as "done" once the helper finished step 4 OK.
//
// The "self-restart" trick mirrors Coolify's helper-container pattern
// but reuses muvon-deployer as the orchestrator. Coolify needs a
// separate helper because their main app must keep running; MUVON's
// admin (muvon) and worker (deployer) are already in different
// containers, so deployer can safely tell Docker to recycle itself.

// upgradeMu serialises SystemUpgrade and CreateBackup: both dump the same
// database into the same directory, so they must not overlap. Combined with the DB
// advisory lock on the admin side this gives us two independent guards.
var upgradeMu sync.Mutex

const (
	helperImage   = "docker:27-cli"
	helperHostMnt = "/host/muvon" // bind mount of /opt/muvon
)

func (s *Server) SystemUpgrade(req *pb.SystemUpgradeRequest, stream pb.DeployerService_SystemUpgradeServer) error {
	// Every event goes to the container log as well as the stream. The stream
	// lives only as long as the operator's browser tab: an upgrade that fails
	// after they navigate away, or one whose reason arrives as the connection
	// drops, used to leave no trace anywhere on the host. "Look at the server
	// log" has to actually work.
	emit := func(step, level, message string, done bool) {
		switch level {
		case "error":
			slog.Error("system upgrade", "step", step, "message", message)
		case "warn":
			slog.Warn("system upgrade", "step", step, "message", message)
		default:
			slog.Info("system upgrade", "step", step, "message", message)
		}
		_ = stream.Send(&pb.UpgradeEvent{
			Step:      step,
			Level:     level,
			Message:   message,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Done:      done,
		})
	}

	if !upgradeMu.TryLock() {
		emit("failed", "error", "another upgrade or backup is already running", true)
		return nil
	}
	defer upgradeMu.Unlock()
	emit("locked", "info", "upgrade lock acquired", false)

	ctx := stream.Context()

	// 1) Pre-check — host'taki /host/muvon mount'ı + Docker socket.
	emit("pre_check", "info", "checking host mounts...", false)
	if _, err := os.Stat(filepath.Join(helperHostMnt, "docker-compose.yml")); err != nil {
		emit("failed", "error", fmt.Sprintf("host compose mount missing: %v (deployer needs /opt/muvon mounted as %s)", err, helperHostMnt), true)
		return nil
	}

	// 2) Hedef tag normalize (v prefix strip, Docker semver convention).
	tag := strings.TrimSpace(req.GetTargetTag())
	if tag == "" {
		tag = "latest"
	}
	tag = strings.TrimPrefix(tag, "v")
	emit("pre_check", "info", fmt.Sprintf("target tag: %s", tag), false)

	// 3) Yedek. Operatör yedek istediyse ve yedek alınamıyorsa upgrade durur:
	//    ağsız bir yedekle devam etmek, yedek var sanılarak yükseltme yapmak
	//    demek ve bu tam olarak bozuk dump'ların fark edilmemesine yol açtı.
	if req.GetTakeBackup() {
		emit("backup", "info", "running pg_dump -Fc...", false)
		path, err := s.runPGDump(ctx, emit)
		if err != nil {
			emit("failed", "error", fmt.Sprintf("backup failed, upgrade aborted: %v "+
				"(re-run with backup disabled to proceed without one)", err), true)
			return nil
		}
		emit("backup", "info", "backup written and verified: "+path, false)
	} else {
		emit("backup", "info", "backup skipped (operator opted out)", false)
	}

	// 4) Helper container'ı başlat + stdout/stderr'i event'e dönüştür
	emit("pull", "info", "spawning muvon-upgrader helper container...", false)
	if err := s.runUpgrader(ctx, emit, tag); err != nil {
		emit("failed", "error", fmt.Sprintf("upgrader failed: %v", err), true)
		return nil
	}

	// 5) Buraya geldiysek helper bizi (deployer) restart etmedi — yeni
	//    image aynı digest ise compose tetiklenmez. Yine de işi başarılı
	//    sayıyoruz; admin UI sürüm karşılaştırmasını yeniden tetikleyecek.
	emit("done", "info", "upgrade completed", true)
	return nil
}

// backupDir is where the dump lands inside the deployer container; compose
// binds the shared "backups" volume here.
const backupDir = "/var/lib/muvon/backups"

// postgresContainer is the compose service name of the database.
const postgresContainer = "muvon-postgres"

// runPGDump execs pg_dump -Fc inside the postgres container and streams its
// stdout straight to disk.
//
// The output is a compressed binary archive, so it must never touch anything
// line-oriented: an earlier version collected it through the container-log
// demuxer, which splits on newlines and trims trailing CR/LF, and silently
// deleted every 0x0A byte. Every dump written that way was unrestorable while
// the upgrade reported "backup written". Streaming also keeps a multi-gigabyte
// archive out of the deployer's heap.
//
// The file is written under a .part name and only renamed once it verifies, so
// a failed attempt cannot be mistaken for a usable backup.
func (s *Server) runPGDump(ctx context.Context, emit func(step, level, msg string, done bool)) (string, error) {
	stamp := time.Now().UTC().Format("20060102-150405")
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return "", err
	}
	outPath := filepath.Join(backupDir, "pgdata-"+stamp+".dump")
	partPath := outPath + ".part"

	f, err := os.OpenFile(partPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	w := bufio.NewWriterSize(f, 1<<20)

	cmd := []string{"pg_dump", "-Fc", "-U", "muvon", "-d", "muvon"}
	code, stderrTail, execErr := s.docker.ContainerExecStream(ctx, postgresContainer, cmd, w)

	flushErr := w.Flush()
	syncErr := f.Sync()
	closeErr := f.Close()

	// A dump that fails its checks is kept, renamed so nothing can mistake it
	// for a usable backup. Deleting the evidence is how a failed backup
	// becomes unexplainable after the fact; the operator needs the file to
	// see what actually came out.
	fail := func(format string, args ...any) (string, error) {
		err := fmt.Errorf(format, args...)
		rejected := outPath + ".rejected"
		if renameErr := os.Rename(partPath, rejected); renameErr != nil {
			os.Remove(partPath)
			slog.Error("backup rejected and could not be preserved",
				"error", err, "rename_error", renameErr)
			return "", err
		}
		size := int64(-1)
		if info, statErr := os.Stat(rejected); statErr == nil {
			size = info.Size()
		}
		slog.Error("backup rejected", "error", err, "kept_at", rejected, "bytes", size)
		return "", fmt.Errorf("%w (rejected file kept at %s)", err, rejected)
	}
	switch {
	case execErr != nil:
		return fail("pg_dump exec failed: %w (stderr: %s)", execErr, strings.TrimSpace(string(stderrTail)))
	case code != 0:
		return fail("pg_dump exited with code %d: %s", code, strings.TrimSpace(string(stderrTail)))
	case flushErr != nil:
		return fail("writing dump: %w", flushErr)
	case syncErr != nil:
		return fail("flushing dump to disk: %w", syncErr)
	case closeErr != nil:
		return fail("closing dump: %w", closeErr)
	}

	if err := verifyCustomDumpHeader(partPath); err != nil {
		return fail("dump failed its header check: %w", err)
	}
	if err := s.verifyDumpRestorable(ctx, filepath.Base(partPath), emit); err != nil {
		return fail("dump failed verification: %w", err)
	}

	if err := os.Rename(partPath, outPath); err != nil {
		return fail("publishing dump: %w", err)
	}
	return outPath, nil
}

// verifyCustomDumpHeader checks the archive header pg_dump writes for -Fc.
// Layout: "PGDMP" magic, then version major/minor/rev, the sizes of the
// integer and offset fields, and the format byte (1 = custom). It costs one
// read and rules out an empty, truncated or rewritten file even on hosts where
// the pg_restore check below cannot run.
func verifyCustomDumpHeader(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() < 64 {
		return fmt.Errorf("archive is only %d bytes", info.Size())
	}

	head := make([]byte, 11)
	if _, err := io.ReadFull(f, head); err != nil {
		return fmt.Errorf("reading archive header: %w", err)
	}
	if string(head[:5]) != "PGDMP" {
		return fmt.Errorf("missing PGDMP magic (got %q)", head[:5])
	}
	// head[5:8] is the version triple, head[8] the int size, head[9] the
	// offset size, head[10] the format.
	if intSize := head[8]; intSize == 0 || intSize > 32 {
		return fmt.Errorf("implausible integer size %d in header", intSize)
	}
	if offSize := head[9]; offSize == 0 || offSize > 32 {
		return fmt.Errorf("implausible offset size %d in header", offSize)
	}
	if format := head[10]; format != 1 {
		return fmt.Errorf("archive format is %d, expected 1 (custom)", format)
	}
	return nil
}

// verifyDumpRestorable runs pg_restore -l over the finished file, which is the
// only check that reads the whole archive rather than trusting its first
// bytes. It runs in a throwaway container built from the postgres image the
// database itself uses, with the same backups storage attached.
//
// When the storage cannot be located the check is skipped with a warning
// rather than failing the upgrade: refusing to upgrade because we could not
// introspect our own mounts would be a worse failure than an unverified
// backup, and the header check has already run.
func (s *Server) verifyDumpRestorable(ctx context.Context, fileName string, emit func(step, level, msg string, done bool)) error {
	pg, err := s.docker.ContainerInspect(ctx, postgresContainer)
	if err != nil {
		emit("backup", "warn", fmt.Sprintf("skipping pg_restore check: cannot inspect %s: %v", postgresContainer, err), false)
		return nil
	}

	bind, err := s.backupStorageBind(ctx)
	if err != nil {
		emit("backup", "warn", "skipping pg_restore check: "+err.Error(), false)
		return nil
	}

	id, logs, wait, err := s.docker.RunHelperContainer(ctx, deployer.HelperContainerOpts{
		Image: pg.ImageRef,
		Cmd:   []string{"pg_restore", "-l", "/verify/" + fileName},
		Binds: []string{bind},
		// The dump is written 0600 root, and the postgres image drops to the
		// postgres user, so without this the check fails with EACCES on a
		// perfectly good archive — which then aborted the upgrade. The
		// container only reads, and the mount is read-only.
		User:       "root",
		AutoRemove: false,
		Labels:     map[string]string{"muvon.helper.kind": "backup-verify"},
	})
	if err != nil {
		emit("backup", "warn", fmt.Sprintf("skipping pg_restore check: %v", err), false)
		return nil
	}
	defer func() {
		_ = s.docker.ContainerRemove(context.Background(), id, true)
	}()

	var out strings.Builder
	if logs != nil {
		_, _ = io.Copy(&out, io.LimitReader(logs, 8*1024))
		_, _ = io.Copy(io.Discard, logs)
		logs.Close()
	}
	code, err := wait()
	if err != nil {
		emit("backup", "warn", fmt.Sprintf("skipping pg_restore check: %v", err), false)
		return nil
	}
	if code != 0 {
		return fmt.Errorf("pg_restore -l exited with %d: %s", code, strings.TrimSpace(out.String()))
	}
	emit("backup", "info", "pg_restore verified the archive", false)
	return nil
}

// backupStorageBind returns a bind spec that gives another container the same
// backup storage this one has, found by reading our own mount table.
func (s *Server) backupStorageBind(ctx context.Context) (string, error) {
	self, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("cannot read own hostname: %w", err)
	}
	insp, err := s.docker.ContainerInspect(ctx, self)
	if err != nil {
		return "", fmt.Errorf("cannot inspect own container %q: %w", self, err)
	}
	for _, m := range insp.Mounts {
		if m.Destination != backupDir {
			continue
		}
		// A named volume is the normal case; mounting it by name lets Docker
		// resolve the storage the same way it did for us.
		if m.Name != "" {
			return m.Name + ":/verify:ro", nil
		}
		if m.Source != "" {
			return m.Source + ":/verify:ro", nil
		}
	}
	return "", fmt.Errorf("no mount found at %s", backupDir)
}

// runUpgrader docker:cli helper container yaratır: compose dosyasını
// github'tan tazeler, hedef tag'i sed ile yazar, `compose pull && up -d`
// çalıştırır. Helper bitince auto-remove. Stdout/stderr event'lere döner.
func (s *Server) runUpgrader(parentCtx context.Context, emit func(step, level, msg string, done bool), target string) error {
	// Helper'ın yaşam döngüsünü gRPC stream'inden ayır: stream koparsa
	// (deployer recreate sırasında olur) helper'ın Docker call'ları
	// iptal olmasın. 12 dakika kendi başına yeterli budget.
	helperCtx, helperCancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer helperCancel()

	if err := s.docker.ImagePull(parentCtx, helperImage); err != nil {
		return fmt.Errorf("pull %s: %w", helperImage, err)
	}

	sedLine := ""
	if target != "" && target != "latest" {
		sedLine = fmt.Sprintf(`sed -i -E "s|(ghcr\\.io/[^:]+):latest|\\1:%s|g" docker-compose.yml`, target)
	}

	// muvon-deployer'ı SONA bırak: helper container bu deployer'ın
	// spawn'ı. set -ex ile her satır echo'lanır, kör failure görmüyoruz.
	script := strings.Join([]string{
		"set -ex",
		"cd " + helperHostMnt,
		"echo '[upgrader] fetching latest compose...'",
		"wget -q -O docker-compose.yml https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/docker-compose.yml",
		sedLine,
		"echo '[upgrader] pulling images...'",
		"docker compose pull muvon dialog-siem muvon-deployer",
		"echo '[upgrader] recreating muvon + dialog-siem...'",
		"docker compose up -d --no-deps --wait --wait-timeout 180 muvon dialog-siem",
		"echo '[upgrader] recreating muvon-deployer (last)...'",
		"docker compose up -d --no-deps --wait --wait-timeout 180 muvon-deployer",
		"echo '[upgrader] done'",
	}, "\n")

	name := "muvon-upgrader-" + time.Now().UTC().Format("20060102-150405")
	id, logs, wait, err := s.docker.RunHelperContainer(helperCtx, deployer.HelperContainerOpts{
		Image: helperImage,
		Name:  name,
		Cmd:   []string{"sh", "-c", script},
		Binds: []string{
			"/var/run/docker.sock:/var/run/docker.sock",
			"/opt/muvon:" + helperHostMnt,
		},
		Labels: map[string]string{"muvon.role": "upgrader"},
		// AutoRemove=false: failure'da carcass kalır, `docker logs <id>`
		// ile son satırlar görülür. Başarılı yolda aşağıda explicit remove.
		AutoRemove: false,
		Init:       true,
	})
	if err != nil {
		return fmt.Errorf("spawn upgrader: %w", err)
	}
	emit("pull", "info", fmt.Sprintf("[upgrader] container: %s", name), false)

	dem := deployer.NewLogDemuxer(logs, deployer.DemuxOptions{MaxLine: 64 * 1024})
	for chunk := range dem.Out() {
		line := strings.TrimRight(chunk.Line, "\r\n")
		if line == "" {
			continue
		}
		emit(classifyUpgraderLine(line), "info", line, false)
	}
	if err := logs.Close(); err != nil && err != io.EOF {
		slog.Debug("upgrader log close", "error", err)
	}

	exit, err := wait()
	if err != nil {
		emit("pull", "error", fmt.Sprintf("[upgrader] wait failed: %v (container %s preserved for inspection)", err, name), false)
		return fmt.Errorf("wait upgrader: %w", err)
	}
	if exit != 0 {
		emit("pull", "error", fmt.Sprintf("[upgrader] container exited %d — preserved as %s for `docker logs`", exit, name), false)
		return fmt.Errorf("upgrader exited with code %d (container %s)", exit, name)
	}
	// Success path: remove the carcass explicitly.
	_ = s.docker.ContainerRemove(context.Background(), id, true)
	return nil
}

// classifyUpgraderLine helper container'ın stdout'undaki marker
// satırlarını adıma map'ler. Helper bilinçli olarak "[upgrader]"
// prefix'iyle adım başlatıyor; geri kalan docker output'u "pull"
// adımının altında kalır.
func classifyUpgraderLine(line string) string {
	switch {
	case strings.Contains(line, "[upgrader] pulling"):
		return "pull"
	case strings.Contains(line, "[upgrader] recreating"):
		return "restart"
	case strings.Contains(line, "[upgrader] done"):
		return "post_check"
	default:
		return "pull"
	}
}
