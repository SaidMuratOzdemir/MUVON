package logger

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ContainerPipeline mirrors Pipeline for container stdout/stderr lines.
// Lighter than the http path: no GeoIP/JWT enrichment, no body fan-out,
// but still does drop-on-overflow with counters and an SSE-friendly
// Subscribe()/Unsubscribe() so the admin live-tail bridge can splice in
// without paying the gRPC round-trip cost on each line.
type ContainerPipeline struct {
	ch       chan ContainerEntry
	pool     *pgxpool.Pool
	workerWg sync.WaitGroup
	quit     chan struct{}
	closed   atomic.Bool
	dropped  atomic.Int64
	enqueued atomic.Int64

	// Health signals reported by SendContainerLogBatch handlers and
	// surfaced through GetIngestStatus. Updated atomically so the read
	// path is lock-free.
	lastBatchUnix     atomic.Int64
	containersActive  atomic.Int64

	// Spool/lag stats reported by the deployer logship over a side
	// channel (UpdateShipperStats). Read by GetIngestStatus.
	shipperMu             sync.RWMutex
	shipperReportedAtUnix int64
	spoolBytes            int64
	spoolOldestUnix       int64

	subMu sync.RWMutex
	subs  map[chan ContainerEntry]struct{}
}

// NewContainerPipeline starts workers immediately and returns a ready
// pipeline. Same shape as NewPipeline so wiring in cmd/dialog-siem stays
// symmetric.
func NewContainerPipeline(pool *pgxpool.Pool, bufferSize, workerCount, batchSize int, flushInterval time.Duration) *ContainerPipeline {
	if bufferSize <= 0 {
		bufferSize = 10000
	}
	if workerCount <= 0 {
		workerCount = 2
	}
	if batchSize <= 0 {
		batchSize = 1000
	}
	if flushInterval <= 0 {
		flushInterval = 2 * time.Second
	}

	p := &ContainerPipeline{
		ch:   make(chan ContainerEntry, bufferSize),
		pool: pool,
		quit: make(chan struct{}),
		subs: make(map[chan ContainerEntry]struct{}),
	}

	for i := 0; i < workerCount; i++ {
		w := newContainerWorker(i, pool, p.ch, batchSize, flushInterval, p.quit)
		p.workerWg.Add(1)
		go func() {
			defer p.workerWg.Done()
			w.run()
		}()
	}

	slog.Info("container log pipeline started",
		"buffer", bufferSize,
		"workers", workerCount,
		"batch", batchSize,
		"flush", flushInterval.String())
	return p
}

// Send enqueues an entry; drops on overflow. Caller must already have
// stamped Seq and Timestamp; ReceivedAt is set here.
func (p *ContainerPipeline) Send(entry ContainerEntry) {
	if p.closed.Load() {
		return
	}
	if entry.ReceivedAt.IsZero() {
		entry.ReceivedAt = time.Now()
	}

	// Auto-detect JSON lines into attrs so the UI can filter on
	// attrs.level/severity without the shipper's involvement. Cheap —
	// one alloc per line, only attempted when the line looks like an
	// object ('{' first byte).
	if len(entry.Attrs) == 0 && len(entry.Line) > 1 && entry.Line[0] == '{' {
		entry.Attrs = parseJSONLine(entry.Line)
	}

	select {
	case p.ch <- entry:
		p.enqueued.Add(1)
	default:
		p.dropped.Add(1)
		slog.Warn("container log pipeline full, dropping entry",
			"dropped_total", p.dropped.Load(),
			"container", entry.ContainerName)
	}

	// SSE fan-out — non-blocking; slow subscriber loses the line.
	p.subMu.RLock()
	for sub := range p.subs {
		select {
		case sub <- entry:
		default:
		}
	}
	p.subMu.RUnlock()
}

// SendBatch is a convenience for handlers that already hold a slice.
// Stamps last_batch_at + active container count for ingest health.
func (p *ContainerPipeline) SendBatch(entries []ContainerEntry, activeContainers int64) {
	if len(entries) == 0 {
		return
	}
	for i := range entries {
		p.Send(entries[i])
	}
	p.lastBatchUnix.Store(time.Now().Unix())
	if activeContainers > 0 {
		p.containersActive.Store(activeContainers)
	}
}

// Subscribe returns a channel that receives every container log entry
// after enqueue. Caller must Unsubscribe to release the slot.
func (p *ContainerPipeline) Subscribe() chan ContainerEntry {
	ch := make(chan ContainerEntry, 256)
	p.subMu.Lock()
	p.subs[ch] = struct{}{}
	p.subMu.Unlock()
	return ch
}

// Unsubscribe removes the subscriber and closes the channel.
func (p *ContainerPipeline) Unsubscribe(ch chan ContainerEntry) {
	p.subMu.Lock()
	delete(p.subs, ch)
	p.subMu.Unlock()
	close(ch)
}

// UpdateShipperStats lets the deployer (or agent dockerwatch) report
// spool size + age so the admin UI can show ingestion-health banners.
// Reported via the SendContainerLogBatch handler's metadata, not a
// dedicated RPC, to avoid a second auth surface.
func (p *ContainerPipeline) UpdateShipperStats(spoolBytes, spoolOldestUnix int64) {
	p.shipperMu.Lock()
	p.shipperReportedAtUnix = time.Now().Unix()
	p.spoolBytes = spoolBytes
	p.spoolOldestUnix = spoolOldestUnix
	p.shipperMu.Unlock()
}

// IngestStats snapshots health state for the GetIngestStatus RPC.
func (p *ContainerPipeline) IngestStats(staleAfter time.Duration) (enqueued, dropped int64, queueLen int, lastBatchAt time.Time, containersActive int64, spoolBytes, spoolOldestSeconds int64, degraded bool) {
	enqueued = p.enqueued.Load()
	dropped = p.dropped.Load()
	queueLen = len(p.ch)
	if v := p.lastBatchUnix.Load(); v > 0 {
		lastBatchAt = time.Unix(v, 0)
	}
	containersActive = p.containersActive.Load()

	p.shipperMu.RLock()
	reportedAtUnix := p.shipperReportedAtUnix
	spoolBytes = p.spoolBytes
	spoolOldestUnix := p.spoolOldestUnix
	p.shipperMu.RUnlock()

	now := time.Now().Unix()
	if reportedAtUnix > 0 && spoolOldestUnix > 0 {
		spoolOldestSeconds = now - spoolOldestUnix
	}
	// Degraded: shipper has not reported within staleAfter, OR spool is
	// non-empty (any spool means dialog-siem couldn't keep up at some
	// point recently — surface it).
	if staleAfter > 0 && reportedAtUnix > 0 && now-reportedAtUnix > int64(staleAfter.Seconds()) {
		degraded = true
	}
	if spoolBytes > 0 {
		degraded = true
	}
	return
}

func (p *ContainerPipeline) Stop() {
	if !p.closed.CompareAndSwap(false, true) {
		return
	}
	slog.Info("container log pipeline shutting down", "queued", len(p.ch))
	close(p.quit)
	close(p.ch)
	p.workerWg.Wait()
	slog.Info("container log pipeline stopped",
		"total_enqueued", p.enqueued.Load(),
		"total_dropped", p.dropped.Load())
}
