package logship

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// SpooledEntry is one line waiting to be shipped. Fields mirror
// SendContainerLogBatch's ContainerLogEntry plus the dimension fields
// the SIEM needs to upsert. Keeping it self-contained per row means
// replay can run without consulting any in-memory state.
type SpooledEntry struct {
	HostID        string            `json:"host_id"`
	ContainerID   string            `json:"container_id"`
	ContainerName string            `json:"container_name"`
	Image         string            `json:"image,omitempty"`
	ImageDigest   string            `json:"image_digest,omitempty"`
	Project       string            `json:"project,omitempty"`
	Component     string            `json:"component,omitempty"`
	ReleaseID     string            `json:"release_id,omitempty"`
	DeploymentID  string            `json:"deployment_id,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	StartedAt     time.Time         `json:"started_at,omitempty"`
	Timestamp     time.Time         `json:"ts"`
	Stream        string            `json:"stream"`
	Line          string            `json:"line"`
	Truncated     bool              `json:"truncated,omitempty"`
	Seq           int64             `json:"seq"`
}

// Spool is an append-only on-disk buffer of SpooledEntry rows, used
// when the dialog-siem connection fails. One file per container
// (sanitised id as filename) keeps replay ordered without an extra
// index. Total disk budget capped; older files truncated when over.
//
// Concurrency: Append, Stats, Drain are all safe for concurrent use.
// Drain holds the spool mutex for the duration of one container's
// drain so a concurrent Append into that file blocks rather than
// interleaves writes — file is JSON-lines and partial lines must
// not be visible to readers.
type Spool struct {
	dir       string
	maxBytes  int64
	maxFile   int64
	mu        sync.Mutex
	curBytes  int64 // best-effort cache of total spool size; refreshed on rescan
	lastScan  time.Time
}

// NewSpool initialises the spool directory and returns a usable Spool.
// Directory is created if missing; an existing dir is used as-is.
func NewSpool(dir string, maxBytes, maxFile int64) (*Spool, error) {
	if dir == "" {
		return nil, errors.New("spool: dir is required")
	}
	if maxBytes <= 0 {
		maxBytes = 256 * 1024 * 1024 // 256 MiB
	}
	if maxFile <= 0 {
		maxFile = 16 * 1024 * 1024 // 16 MiB
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("spool: mkdir %s: %w", dir, err)
	}
	s := &Spool{
		dir:      dir,
		maxBytes: maxBytes,
		maxFile:  maxFile,
	}
	s.recomputeBytes() // best-effort initial total
	return s, nil
}

// containerFile returns the safe filename for a container id.
func (s *Spool) containerFile(containerID string) string {
	clean := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, containerID)
	if len(clean) > 96 {
		clean = clean[:96]
	}
	return filepath.Join(s.dir, clean+".spool")
}

// Append writes the entries to the per-container spool file. On
// quota overflow, the oldest spool file is truncated; the request
// itself is never refused — losing the oldest is preferable to
// dropping the live tail.
func (s *Spool) Append(containerID string, entries []SpooledEntry) error {
	if containerID == "" || len(entries) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// Enforce file quota first — if this single container's file is
	// about to exceed maxFile, rotate by truncating it. Logship semantics:
	// if a single container is very chatty, we'd rather lose its older
	// spooled lines than drop everyone else's.
	path := s.containerFile(containerID)
	if fi, err := os.Stat(path); err == nil && fi.Size() >= s.maxFile {
		s.curBytes -= fi.Size()
		_ = os.Truncate(path, 0)
	}

	// Enforce global quota — if appending would push us over, evict
	// the oldest *other* container's file until we fit.
	encoded := make([][]byte, 0, len(entries))
	approx := int64(0)
	for _, e := range entries {
		b, err := json.Marshal(e)
		if err != nil {
			continue
		}
		encoded = append(encoded, b)
		approx += int64(len(b)) + 1
	}
	for s.curBytes+approx > s.maxBytes {
		if !s.evictOldestExcept(containerID) {
			break
		}
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("spool: open %s: %w", path, err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, b := range encoded {
		if _, err := w.Write(b); err != nil {
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	s.curBytes += approx
	return nil
}

// Drain reads the spool file for a container, hands its entries (in
// batches of batchSize) to send, and rotates the file when send
// returns nil. send returning a non-nil error stops the drain — the
// remaining tail stays on disk for the next attempt.
//
// While drain is in progress for a container, Append for that same
// container blocks (mutex). This prevents a partial-line race during
// the rename + truncate dance below.
//
// Returns the number of entries successfully shipped.
func (s *Spool) Drain(containerID string, batchSize int, send func([]SpooledEntry) error) (int, error) {
	if containerID == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.containerFile(containerID)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	if batchSize <= 0 {
		batchSize = 500
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var batch []SpooledEntry
	shipped := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := send(batch); err != nil {
			return err
		}
		shipped += len(batch)
		batch = batch[:0]
		return nil
	}
	for scanner.Scan() {
		var e SpooledEntry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			// Skip malformed line — newer entries are still valuable.
			continue
		}
		batch = append(batch, e)
		if len(batch) >= batchSize {
			if err := flush(); err != nil {
				return shipped, err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		// Treat read errors as terminal for this drain pass; spool
		// still on disk, retry later.
		return shipped, err
	}
	if err := flush(); err != nil {
		return shipped, err
	}

	// All entries shipped — remove the file. Best-effort: if the file
	// disappeared concurrently (it shouldn't given the lock) ignore.
	if fi, err := os.Stat(path); err == nil {
		s.curBytes -= fi.Size()
		if s.curBytes < 0 {
			s.curBytes = 0
		}
	}
	_ = os.Remove(path)
	return shipped, nil
}

// Stats returns total bytes on disk and the age of the oldest spooled
// file. age == 0 when the spool is empty.
func (s *Spool) Stats() (totalBytes int64, oldest time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Refresh cache periodically (cheap dir scan).
	if time.Since(s.lastScan) > 5*time.Second {
		s.recomputeBytes()
	}
	totalBytes = s.curBytes
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".spool") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if oldest.IsZero() || fi.ModTime().Before(oldest) {
			oldest = fi.ModTime()
		}
	}
	return
}

// PendingContainers lists container_ids that currently have a non-empty
// spool file. Used by the manager on startup or reconnect to drain
// historic state.
func (s *Spool) PendingContainers() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingLocked()
}

func (s *Spool) pendingLocked() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".spool") {
			continue
		}
		fi, err := e.Info()
		if err != nil || fi.Size() == 0 {
			continue
		}
		// Filename = sanitised container id; we cannot reconstruct
		// the original id from the sanitised version, so the manager
		// must read entries inside the file to discover the id. We
		// expose the sanitised name here as a key for ordering.
		out = append(out, strings.TrimSuffix(e.Name(), ".spool"))
	}
	return out, nil
}

// recomputeBytes refreshes the in-memory total. Lock must be held.
func (s *Spool) recomputeBytes() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		total += fi.Size()
	}
	s.curBytes = total
	s.lastScan = time.Now()
}

// evictOldestExcept removes the oldest non-empty spool file other than
// the one for `keepID`. Returns true if eviction freed bytes, false when
// nothing else with content exists. Critical to skip empty files —
// otherwise a single recently-truncated file would be the "oldest"
// forever and the caller's quota loop would spin.
func (s *Spool) evictOldestExcept(keepID string) bool {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return false
	}
	keepName := filepath.Base(s.containerFile(keepID))
	type fileInfo struct {
		name    string
		modTime time.Time
		size    int64
	}
	candidates := make([]fileInfo, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".spool") {
			continue
		}
		if e.Name() == keepName {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if fi.Size() == 0 {
			// Already empty — clean it up but don't count as eviction.
			_ = os.Remove(filepath.Join(s.dir, e.Name()))
			continue
		}
		candidates = append(candidates, fileInfo{name: e.Name(), modTime: fi.ModTime(), size: fi.Size()})
	}
	if len(candidates) == 0 {
		return false
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].modTime.Before(candidates[j].modTime) })
	victim := candidates[0]
	path := filepath.Join(s.dir, victim.name)
	if err := os.Remove(path); err != nil {
		slog.Warn("spool: remove victim failed", "path", path, "error", err)
		return false
	}
	s.curBytes -= victim.size
	if s.curBytes < 0 {
		s.curBytes = 0
	}
	slog.Warn("spool: evicted oldest container's queue to stay under quota",
		"victim", victim.name,
		"freed_bytes", victim.size)
	return true
}

// AllContainerIDs scans every spool file and returns the unique
// container_id values it finds inside. Used by the manager on startup
// to drain spools whose container is gone (so we don't need the
// inverse map from sanitised filename → id).
func (s *Spool) AllContainerIDs() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(entries))
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".spool") {
			continue
		}
		path := filepath.Join(s.dir, e.Name())
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		// Read just the first line — every entry in the file has the
		// same container_id by construction.
		br := bufio.NewReader(f)
		line, err := br.ReadBytes('\n')
		f.Close()
		if err != nil && err != io.EOF {
			continue
		}
		if len(line) == 0 {
			continue
		}
		var probe SpooledEntry
		if err := json.Unmarshal(line, &probe); err != nil || probe.ContainerID == "" {
			continue
		}
		if _, ok := seen[probe.ContainerID]; !ok {
			seen[probe.ContainerID] = struct{}{}
			out = append(out, probe.ContainerID)
		}
	}
	return out, nil
}
