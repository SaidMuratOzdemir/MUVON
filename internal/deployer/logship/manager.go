package logship

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"muvon/internal/deployer"
	logclient "muvon/internal/logger/grpcclient"
	pb "muvon/proto/logpb"
)

// Manager attaches a tail goroutine per managed container and ships
// stdout/stderr lines to dialog-siem. On send failure it persists the
// batch to the on-disk Spool so the next reconnect can replay. Reacts
// to docker /events: spawns on `start`, retires on `die`/`destroy`.
//
// Lifecycle:
//
//   1. Run() — Start logship.
//      a. Drain any pre-existing spool files (containers from a previous
//         deployer process that died with logs in flight).
//      b. ContainerListAll(managedOnly=true) → spawn a tail goroutine
//         per container.
//      c. EventsStream → react to lifecycle events.
//      d. Periodic flush + spool replay loop in case dialog-siem was
//         transiently down.
//   2. Run returns when ctx is canceled. tail goroutines exit on their
//      own as the per-tail context is canceled.
//
// All public methods are safe for concurrent use.
type Manager struct {
	docker      *deployer.DockerClient
	sink        *logclient.RemoteLogSink
	spool       *Spool
	hostID      string // "central" or agent UUID/hostname
	maxLine     int
	batchSize   int
	flushEvery  time.Duration
	// managedOnly=true filters tails to containers carrying
	// muvon.managed=true (central host: only deploys we control).
	// =false ships every container on the host (agent host: operator
	// has no deployer painting the label, so we cover everything).
	managedOnly bool

	// Active tails keyed by container_id.
	mu     sync.Mutex
	tails  map[string]*tailState
	active atomic.Int32

	// lastTS tracks the most recent line timestamp seen per container.
	// Updated on every chunk processed. tailLoop uses it to compute
	// `since` when the upstream Docker logs stream needs to be
	// (re)opened — without this, a deployer restart would re-ingest
	// the last 10k lines from Docker's json-file driver and create
	// duplicate hypertable rows.
	lastTSMu sync.RWMutex
	lastTS   map[string]time.Time

	// Reporting helpers.
	pipelineLagFn func(spoolBytes, oldestUnix int64) // optional dialog-siem health update
}

type tailState struct {
	cancel context.CancelFunc
	meta   ContainerMeta
}

// ContainerMeta is the dimension info we need for every batch. Set once
// when the tail attaches; the shipper does not chase down stale labels
// while the container runs.
type ContainerMeta struct {
	ContainerID   string
	ContainerName string
	Image         string
	ImageDigest   string
	Project       string
	Component     string
	ReleaseID     string
	HostID        string
	Labels        map[string]string
	StartedAt     time.Time
}

// Options tunes the manager. Zero values fall back to safe defaults.
type Options struct {
	HostID      string
	MaxLine     int
	BatchSize   int
	Flush       time.Duration
	OnLagUpdate func(spoolBytes, oldestUnix int64)
	// ManagedOnly: when true (default for central), only containers
	// labelled muvon.managed=true are tailed. When false (agent host),
	// every container on the local Docker daemon is tailed.
	ManagedOnly bool
}

// New wires a Manager. docker + sink + spool are required; opts may be
// the zero value.
func New(docker *deployer.DockerClient, sink *logclient.RemoteLogSink, spool *Spool, opts Options) *Manager {
	if opts.MaxLine <= 0 {
		opts.MaxLine = 16 * 1024
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 500
	}
	if opts.Flush <= 0 {
		opts.Flush = 1 * time.Second
	}
	if opts.HostID == "" {
		opts.HostID = "central"
	}
	return &Manager{
		docker:        docker,
		sink:          sink,
		spool:         spool,
		hostID:        opts.HostID,
		maxLine:       opts.MaxLine,
		batchSize:     opts.BatchSize,
		flushEvery:    opts.Flush,
		managedOnly:   opts.ManagedOnly,
		tails:         make(map[string]*tailState),
		lastTS:        make(map[string]time.Time),
		pipelineLagFn: opts.OnLagUpdate,
	}
}

// ActiveCount reports how many container tails are currently running.
// Plumbed into deployer's Health RPC.
func (m *Manager) ActiveCount() int32 { return m.active.Load() }

// Run is the manager's main loop. It returns when ctx is canceled.
// Errors during initial enumeration / event subscription are logged
// and retried — the manager keeps running so a transient docker hiccup
// does not orphan logship for the rest of the process lifetime.
func (m *Manager) Run(ctx context.Context) {
	slog.Info("logship: starting",
		"host_id", m.hostID,
		"max_line", m.maxLine,
		"batch", m.batchSize)

	// 1. Drain any spool files left over from a previous run. Doing
	// this before subscribing to events ensures we attempt the older
	// data first; live tail then layers on top.
	m.replaySpool(ctx)

	// 2. Enumerate currently-managed containers and attach.
	if err := m.attachExisting(ctx); err != nil {
		slog.Warn("logship: initial enumeration failed", "error", err)
	}

	// 3. Subscribe to events with backoff. Each subscription runs
	// until the docker daemon disconnects; outer loop restarts on
	// disconnect.
	go m.runEventsLoop(ctx)

	// 4. Periodic spool replay — handles the case where dialog-siem
	// is down for a while; we keep accumulating in spool and try
	// to flush it every few seconds.
	go m.runReplayLoop(ctx)

	<-ctx.Done()
	m.shutdown()
}

func (m *Manager) shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, t := range m.tails {
		t.cancel()
		delete(m.tails, id)
	}
	m.active.Store(0)
}

// attachExisting lists every running container the manager cares about
// (managed-only or all per options) and starts a tail for each. Safety
// net after events-stream reconnects.
func (m *Manager) attachExisting(ctx context.Context) error {
	containers, err := m.docker.ContainerListAll(ctx, m.managedOnly)
	if err != nil {
		return err
	}
	for _, c := range containers {
		if c.State != "running" {
			continue
		}
		m.startTail(ctx, c.ID, summaryToMeta(c, m.hostID))
	}
	return nil
}

// runEventsLoop subscribes to docker /events and dispatches container
// lifecycle hooks. On stream errors it backs off and reconnects; in
// between reconnects we re-enumerate to recover any missed `start`s.
func (m *Manager) runEventsLoop(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		evCh, errCh, err := m.docker.EventsStream(ctx)
		if err != nil {
			slog.Warn("logship: events subscribe failed", "error", err, "retry_in", backoff.String())
			time.Sleep(backoff)
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			continue
		}
		backoff = time.Second
		_ = m.attachExisting(ctx) // best-effort safety net after reconnect

	consume:
		for {
			select {
			case ev, ok := <-evCh:
				if !ok {
					break consume
				}
				m.handleEvent(ctx, ev)
			case err := <-errCh:
				if err != nil && !errors.Is(err, context.Canceled) {
					slog.Warn("logship: events stream error", "error", err)
				}
				break consume
			case <-ctx.Done():
				return
			}
		}
	}
}

func (m *Manager) handleEvent(ctx context.Context, ev deployer.ContainerEvent) {
	if m.managedOnly && ev.Labels["muvon.managed"] != "true" {
		// On central we only ship logs for containers we deploy
		// (matches the E3 product decision: app logs only, not
		// platform). On agent hosts (managedOnly=false) we ship every
		// container the operator runs.
		return
	}
	switch ev.Kind {
	case deployer.ContainerEventStart:
		// Inspect for a richer snapshot (Image digest, etc.).
		insp, err := m.docker.ContainerInspect(ctx, ev.ID)
		if err != nil {
			slog.Warn("logship: inspect on start failed", "id", shortID(ev.ID), "error", err)
			return
		}
		m.startTail(ctx, ev.ID, inspectToMeta(insp, m.hostID))
	case deployer.ContainerEventDie, deployer.ContainerEventDestroy, deployer.ContainerEventStop:
		m.stopTail(ev.ID, finishedFromEvent(ev))
	}
}

// startTail launches a goroutine that streams the container's stdout +
// stderr from Docker and ships batches. Idempotent — calling twice for
// the same container is a no-op.
func (m *Manager) startTail(parentCtx context.Context, containerID string, meta ContainerMeta) {
	m.mu.Lock()
	if _, ok := m.tails[containerID]; ok {
		m.mu.Unlock()
		return
	}
	tailCtx, cancel := context.WithCancel(parentCtx)
	m.tails[containerID] = &tailState{cancel: cancel, meta: meta}
	m.active.Add(1)
	m.mu.Unlock()

	go m.tailLoop(tailCtx, containerID, meta)
}

func (m *Manager) stopTail(containerID string, finishedAt time.Time) {
	m.mu.Lock()
	t, ok := m.tails[containerID]
	if !ok {
		m.mu.Unlock()
		return
	}
	delete(m.tails, containerID)
	m.mu.Unlock()
	m.active.Add(-1)
	t.cancel()

	// Send a final dimension update so the SIEM marks finished_at.
	if !finishedAt.IsZero() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		batch := &pb.ContainerLogBatch{Meta: metaToProto(t.meta, &finishedAt, 0)}
		if err := m.sink.SendContainerLogBatch(ctx, batch); err != nil {
			// Spool the dimension-only update so SIEM still gets the
			// finished marker on the next replay.
			_ = m.spool.Append(t.meta.ContainerID, []SpooledEntry{
				dimensionMarker(t.meta, &finishedAt),
			})
		}
	}
}

// tailLoop opens the multiplexed log stream and pumps batches.
// Terminates on container exit (EOF), context cancel, or repeated send
// failure (spool kicks in).
//
// Resume strategy:
//   - In-memory lastTS[containerID] is checked first. Populated when an
//     earlier tail saw lines for this container in the same process.
//   - On cold start (empty memory), we ask dialog-siem for the latest
//     ingested timestamp via GetContainerLastLogAt.
//   - If neither has a value, the container is brand new to us and we
//     fall back to a tail-based backfill (10k lines) so we get whatever
//     Docker's json-file driver still has buffered.
//
// Without this, every deployer restart re-ingests the last 10k lines of
// every running container.
func (m *Manager) tailLoop(ctx context.Context, containerID string, meta ContainerMeta) {
	since := m.resumePoint(ctx, containerID)
	opts := deployer.ContainerLogsOptions{
		Stdout:     true,
		Stderr:     true,
		Follow:     true,
		Timestamps: true,
	}
	if !since.IsZero() {
		// Docker's `since` is inclusive; bump by 1ns so the boundary
		// line (already ingested) is not re-shipped.
		opts.Since = since.Add(time.Nanosecond)
	} else {
		// First time we see this container. Pull whatever Docker still
		// has buffered — caps at 10k lines so a chatty container does
		// not flood us at attach time.
		opts.Tail = "10000"
	}
	body, err := m.docker.ContainerLogs(ctx, containerID, opts)
	if err != nil {
		slog.Warn("logship: ContainerLogs open failed",
			"id", shortID(containerID),
			"error", err)
		return
	}
	defer body.Close()

	dem := deployer.NewLogDemuxer(body, deployer.DemuxOptions{
		MaxLine:       m.maxLine,
		Buffer:        2048,
		HasTimestamps: true,
	})

	batch := make([]SpooledEntry, 0, m.batchSize)
	flushTimer := time.NewTimer(m.flushEvery)
	defer flushTimer.Stop()

	flush := func(force bool) {
		if len(batch) == 0 {
			return
		}
		if !force && len(batch) < m.batchSize {
			return
		}
		m.shipOrSpool(meta, batch)
		batch = batch[:0]
		// Reset timer so we don't immediately fire after a full-batch
		// flush.
		if !flushTimer.Stop() {
			select {
			case <-flushTimer.C:
			default:
			}
		}
		flushTimer.Reset(m.flushEvery)
	}

	for {
		select {
		case <-ctx.Done():
			flush(true)
			return
		case <-flushTimer.C:
			flush(true)
			flushTimer.Reset(m.flushEvery)
		case chunk, ok := <-dem.Out():
			if !ok {
				flush(true)
				return
			}
			ts := chunkTimestamp(chunk)
			batch = append(batch, SpooledEntry{
				HostID:        meta.HostID,
				ContainerID:   meta.ContainerID,
				ContainerName: meta.ContainerName,
				Image:         meta.Image,
				ImageDigest:   meta.ImageDigest,
				Project:       meta.Project,
				Component:     meta.Component,
				ReleaseID:     meta.ReleaseID,
				Labels:        meta.Labels,
				StartedAt:     meta.StartedAt,
				Timestamp:     ts,
				Stream:        chunk.Stream,
				Line:          chunk.Line,
				Truncated:     chunk.Truncated,
				Seq:           chunk.Seq,
			})
			// Track the latest timestamp we've enqueued so a future
			// reconnect knows where to resume. Updated even before the
			// batch ships — duplicate suppression via `since` is
			// best-effort; the worst case after a hard crash mid-batch
			// is a few seconds of overlap, not 10k lines.
			m.markSeen(containerID, ts)
			if len(batch) >= m.batchSize {
				flush(false)
			}
		}
	}
}

// shipOrSpool tries dialog-siem first; on failure spools to disk. The
// SIEM is the authoritative store so we always check it first.
func (m *Manager) shipOrSpool(meta ContainerMeta, batch []SpooledEntry) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pbBatch := buildPBBatch(meta, batch)
	if err := m.sink.SendContainerLogBatch(ctx, pbBatch); err == nil {
		m.notifyLag()
		return
	} else {
		slog.Debug("logship: send failed; spooling", "container", shortID(meta.ContainerID), "error", err)
	}
	if err := m.spool.Append(meta.ContainerID, batch); err != nil {
		slog.Warn("logship: spool append failed",
			"container", shortID(meta.ContainerID),
			"error", err)
	}
	m.notifyLag()
}

// runReplayLoop periodically attempts to drain spool files. Useful when
// dialog-siem was down for a while and we want to recover without
// waiting for the next batch from the live tail.
func (m *Manager) runReplayLoop(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.replaySpool(ctx)
		}
	}
}

// replaySpool walks every spool file and tries to flush its contents.
func (m *Manager) replaySpool(ctx context.Context) {
	ids, err := m.spool.AllContainerIDs()
	if err != nil {
		slog.Warn("logship: spool scan failed", "error", err)
		return
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		_, err := m.spool.Drain(id, m.batchSize, func(entries []SpooledEntry) error {
			meta := metaFromSpooled(entries)
			pbBatch := buildPBBatch(meta, entries)
			sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			return m.sink.SendContainerLogBatch(sendCtx, pbBatch)
		})
		if err != nil {
			// Stop draining further containers if one fails — likely
			// the SIEM is still down and we'd just bash our head
			// against the wall for the rest.
			return
		}
	}
	m.notifyLag()
}

// resumePoint determines where the next ContainerLogs stream should
// resume from. Memory wins (cheaper than an RPC); on cold-start we ask
// dialog-siem; if both are empty, return zero (caller falls back to
// tail-based backfill).
func (m *Manager) resumePoint(ctx context.Context, containerID string) time.Time {
	m.lastTSMu.RLock()
	if t, ok := m.lastTS[containerID]; ok && !t.IsZero() {
		m.lastTSMu.RUnlock()
		return t
	}
	m.lastTSMu.RUnlock()

	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	t, err := m.sink.GetContainerLastLogAt(probeCtx, containerID)
	if err != nil {
		// dialog-siem unreachable / first-time install / RPC missing:
		// fall through to tail-based backfill.
		return time.Time{}
	}
	if !t.IsZero() {
		m.lastTSMu.Lock()
		m.lastTS[containerID] = t
		m.lastTSMu.Unlock()
	}
	return t
}

// markSeen records that we've enqueued a line for this container at ts.
// Only advances the stored value (older timestamps are ignored, which
// matters when an out-of-order Docker frame slips through).
func (m *Manager) markSeen(containerID string, ts time.Time) {
	if ts.IsZero() {
		return
	}
	m.lastTSMu.Lock()
	defer m.lastTSMu.Unlock()
	if cur, ok := m.lastTS[containerID]; !ok || ts.After(cur) {
		m.lastTS[containerID] = ts
	}
}

func (m *Manager) notifyLag() {
	if m.pipelineLagFn == nil {
		return
	}
	bytes, oldest := m.spool.Stats()
	var oldestUnix int64
	if !oldest.IsZero() {
		oldestUnix = oldest.Unix()
	}
	m.pipelineLagFn(bytes, oldestUnix)
}

// --- helpers ---

func summaryToMeta(c deployer.ContainerSummary, hostID string) ContainerMeta {
	name := ""
	if len(c.Names) > 0 {
		name = strings.TrimPrefix(c.Names[0], "/")
	}
	startedAt := time.Time{}
	if c.Created > 0 {
		startedAt = time.Unix(c.Created, 0)
	}
	return ContainerMeta{
		ContainerID:   c.ID,
		ContainerName: name,
		Image:         c.Image,
		Project:       c.Labels["muvon.project"],
		Component:     c.Labels["muvon.component"],
		ReleaseID:     c.Labels["muvon.release_id"],
		HostID:        hostID,
		Labels:        c.Labels,
		StartedAt:     startedAt,
	}
}

func inspectToMeta(i deployer.ContainerInspectResult, hostID string) ContainerMeta {
	return ContainerMeta{
		ContainerID:   i.ID,
		ContainerName: i.Name,
		Image:         i.ImageRef,
		ImageDigest:   i.Image,
		Project:       i.Labels["muvon.project"],
		Component:     i.Labels["muvon.component"],
		ReleaseID:     i.Labels["muvon.release_id"],
		HostID:        hostID,
		Labels:        i.Labels,
		StartedAt:     i.StartedAt,
	}
}

func metaFromSpooled(entries []SpooledEntry) ContainerMeta {
	if len(entries) == 0 {
		return ContainerMeta{}
	}
	e := entries[0]
	return ContainerMeta{
		ContainerID:   e.ContainerID,
		ContainerName: e.ContainerName,
		Image:         e.Image,
		ImageDigest:   e.ImageDigest,
		Project:       e.Project,
		Component:     e.Component,
		ReleaseID:     e.ReleaseID,
		HostID:        e.HostID,
		Labels:        e.Labels,
		StartedAt:     e.StartedAt,
	}
}

func buildPBBatch(meta ContainerMeta, entries []SpooledEntry) *pb.ContainerLogBatch {
	pbEntries := make([]*pb.ContainerLogEntry, 0, len(entries))
	for _, e := range entries {
		ts := e.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		pbEntries = append(pbEntries, &pb.ContainerLogEntry{
			Timestamp: ts.UTC().Format(time.RFC3339Nano),
			Stream:    e.Stream,
			Line:      e.Line,
			Truncated: e.Truncated,
			Seq:       e.Seq,
		})
	}
	return &pb.ContainerLogBatch{
		Meta:    metaToProto(meta, nil, 0),
		Entries: pbEntries,
	}
}

func metaToProto(meta ContainerMeta, finishedAt *time.Time, exitCode int32) *pb.ContainerMeta {
	pbMeta := &pb.ContainerMeta{
		ContainerId:   meta.ContainerID,
		ContainerName: meta.ContainerName,
		Image:         meta.Image,
		ImageDigest:   meta.ImageDigest,
		Project:       meta.Project,
		Component:     meta.Component,
		ReleaseId:     meta.ReleaseID,
		HostId:        meta.HostID,
		Labels:        meta.Labels,
	}
	if !meta.StartedAt.IsZero() {
		pbMeta.StartedAt = meta.StartedAt.UTC().Format(time.RFC3339)
	}
	if finishedAt != nil && !finishedAt.IsZero() {
		pbMeta.FinishedAt = finishedAt.UTC().Format(time.RFC3339)
		pbMeta.ExitCode = exitCode
	}
	return pbMeta
}

func dimensionMarker(meta ContainerMeta, finishedAt *time.Time) SpooledEntry {
	// Carries finished_at as an empty-line entry with seq=-1 so the
	// SIEM upserts the dimension; line is filtered server-side via a
	// nil/empty check. Cheap way to avoid a second RPC.
	return SpooledEntry{
		HostID:        meta.HostID,
		ContainerID:   meta.ContainerID,
		ContainerName: meta.ContainerName,
		Image:         meta.Image,
		ImageDigest:   meta.ImageDigest,
		Project:       meta.Project,
		Component:     meta.Component,
		ReleaseID:     meta.ReleaseID,
		Labels:        meta.Labels,
		StartedAt:     meta.StartedAt,
		Timestamp:     time.Now(),
		Stream:        "stdout",
		Line:          "",
		Seq:           -1,
	}
}

func chunkTimestamp(c deployer.LogChunk) time.Time {
	if !c.Timestamp.IsZero() {
		return c.Timestamp
	}
	return time.Now()
}

func finishedFromEvent(ev deployer.ContainerEvent) time.Time {
	if !ev.Time.IsZero() {
		return ev.Time
	}
	return time.Now()
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
