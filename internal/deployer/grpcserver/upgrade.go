package grpcserver

import (
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

// upgradeMu serialises SystemUpgrade calls. Combined with the DB
// advisory lock on the admin side this gives us two independent guards.
var upgradeMu sync.Mutex

const (
	helperImage   = "docker:27-cli"
	helperHostMnt = "/host/muvon" // bind mount of /opt/muvon
)

func (s *Server) SystemUpgrade(req *pb.SystemUpgradeRequest, stream pb.DeployerService_SystemUpgradeServer) error {
	emit := func(step, level, message string, done bool) {
		_ = stream.Send(&pb.UpgradeEvent{
			Step:      step,
			Level:     level,
			Message:   message,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Done:      done,
		})
	}

	if !upgradeMu.TryLock() {
		emit("failed", "error", "another upgrade is already in progress", true)
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

	// 2) Hedef tag'i .env'e yaz (VERSION=<tag>). install.sh ile aynı
	//    semantik: yoksa append, varsa overwrite.
	tag := strings.TrimSpace(req.GetTargetTag())
	if tag == "" {
		tag = "latest"
	}
	if err := writeEnvVersion(filepath.Join(helperHostMnt, ".env"), tag); err != nil {
		emit("failed", "error", fmt.Sprintf("write .env failed: %v", err), true)
		return nil
	}
	emit("pre_check", "info", fmt.Sprintf("target tag: %s", tag), false)

	// 3) Yedek
	if req.GetTakeBackup() {
		emit("backup", "info", "running pg_dump -Fc...", false)
		if path, err := s.runPGDump(ctx); err != nil {
			emit("backup", "warn", fmt.Sprintf("backup skipped: %v", err), false)
		} else {
			emit("backup", "info", "backup written: "+path, false)
		}
	} else {
		emit("backup", "info", "backup skipped (operator opted out)", false)
	}

	// 4) Helper container'ı başlat + stdout/stderr'i event'e dönüştür
	emit("pull", "info", "spawning muvon-upgrader helper container...", false)
	if err := s.runUpgrader(ctx, emit); err != nil {
		emit("failed", "error", fmt.Sprintf("upgrader failed: %v", err), true)
		return nil
	}

	// 5) Buraya geldiysek helper bizi (deployer) restart etmedi — yeni
	//    image aynı digest ise compose tetiklenmez. Yine de işi başarılı
	//    sayıyoruz; admin UI sürüm karşılaştırmasını yeniden tetikleyecek.
	emit("done", "info", "upgrade completed", true)
	return nil
}

// writeEnvVersion .env dosyasında VERSION satırını set/append eder.
// install.sh ile aynı pattern; mevcut diğer satırlar dokunulmaz.
func writeEnvVersion(path, tag string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	found := false
	for i, l := range lines {
		if strings.HasPrefix(l, "VERSION=") {
			lines[i] = "VERSION=" + tag
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, "VERSION="+tag)
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600)
}

// runPGDump postgres container'a exec edip pg_dump -Fc'yi tetikler ve
// /var/lib/muvon/backups/ altına yazar. Compose servisi adı sabit:
// "muvon-postgres". Çıktı dosya yolunu döner.
func (s *Server) runPGDump(ctx context.Context) (string, error) {
	stamp := time.Now().UTC().Format("20060102-150405")
	dir := "/var/lib/muvon/backups"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	outPath := filepath.Join(dir, "pgdata-"+stamp+".dump")
	cmd := []string{"pg_dump", "-Fc", "-U", "muvon", "-d", "muvon"}
	stdout, err := s.docker.ContainerExecCapture(ctx, "muvon-postgres", cmd)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(outPath, stdout, 0o600); err != nil {
		return "", err
	}
	return outPath, nil
}

// runUpgrader docker:cli image'ından geçici bir container yaratır,
// host'tan compose dosyasını alarak `compose pull && up -d` çalıştırır
// ve stdout/stderr'i event'lere dönüştürür. Helper bitince auto-remove.
func (s *Server) runUpgrader(ctx context.Context, emit func(step, level, msg string, done bool)) error {
	// Önce image'ı pull et — operator sunucusunda yoksa ilk seferde lazım.
	if err := s.docker.ImagePull(ctx, helperImage); err != nil {
		return fmt.Errorf("pull %s: %w", helperImage, err)
	}

	// docker compose v2 plugin paketi docker:cli image'ında dahili.
	// --wait sağlık beklenir; --wait-timeout 120s.
	script := strings.Join([]string{
		"set -e",
		"cd " + helperHostMnt,
		"echo '[upgrader] pulling images...'",
		"docker compose pull muvon dialog-siem muvon-deployer",
		"echo '[upgrader] recreating containers...'",
		"docker compose up -d --wait --wait-timeout 120",
		"echo '[upgrader] done'",
	}, "\n")

	name := "muvon-upgrader-" + time.Now().UTC().Format("20060102-150405")
	id, logs, wait, err := s.docker.RunHelperContainer(ctx, deployer.HelperContainerOpts{
		Image: helperImage,
		Name:  name,
		Cmd:   []string{"sh", "-c", script},
		Binds: []string{
			"/var/run/docker.sock:/var/run/docker.sock",
			"/opt/muvon:" + helperHostMnt,
		},
		Labels:     map[string]string{"muvon.role": "upgrader"},
		AutoRemove: true,
	})
	if err != nil {
		return fmt.Errorf("spawn upgrader: %w", err)
	}
	_ = id

	// Drain logs in foreground — we want them sequenced with the wait.
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
		return fmt.Errorf("wait upgrader: %w", err)
	}
	if exit != 0 {
		return fmt.Errorf("upgrader exited with code %d", exit)
	}
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
