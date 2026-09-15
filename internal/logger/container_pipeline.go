package logger

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/semaphore"
)

// ErrContainerPipelineClosed is returned for a batch that arrives while the
// pipeline is shutting down. The shipper spools it and resends to the next
// process.
var ErrContainerPipelineClosed = errors.New("container log pipeline is closed")

// ErrContainerPipelineFull is returned when a batch cannot be admitted before
// the caller's deadline. Nothing from that batch was accepted, so a resend
// cannot duplicate anything.
var ErrContainerPipelineFull = errors.New("container log pipeline is full")

// ContainerPipeline stores container stdout/stderr lines and acknowledges a
// batch only once it is committed.
//
// Acknowledgement after commit is the point of the type. A shipper that has
// been told "ok" deletes nothing it could resend, so any loss between the
// acknowledgement and the database is permanent, and invisible: an overflow
// drop or a failed COPY used to look like success to the sender. Here a batch
// is admitted whole or refused whole, and a refusal or a failed write reaches
// the shipper as an error, which it answers by spooling and resending.
//
// Admission is bounded by the number of lines in flight rather than by a
// channel of lines, so a batch is taken atomically: it never happens that half
// of a batch is queued when the buffer fills.
type ContainerPipeline struct {
	store    containerStore
	sem      *semaphore.Weighted
	capacity int64

	jobsMu sync.RWMutex // guards jobs against a send racing Stop's close
	jobs   chan *containerJob
	closed atomic.Bool

	workerWg sync.WaitGroup

	hook atomic.Pointer[containerHookHolder]

	enqueued atomic.Int64
	rejected atomic.Int64
	inFlight atomic.Int64

	// Health signals surfaced through GetIngestStatus.
	lastBatchUnix    atomic.Int64
	containersActive atomic.Int64

	shipperMu             sync.RWMutex
	shipperReportedAtUnix int64
	spoolBytes            int64
	spoolOldestUnix       int64
}

// containerHookHolder exists because atomic.Pointer needs a concrete type and
// the hook is an interface.
type containerHookHolder struct{ hook ContainerCommitHook }

// StoredContainerLine is a line as it is written: the entry plus the row id and
// the timestamp the row carries. Both are fixed before the first write attempt,
// so a retry of the same batch writes the same ids.
type StoredContainerLine struct {
	ID        uuid.UUID
	Timestamp time.Time
	Stream    string
	Entry     ContainerEntry
}

// ContainerCommitHook lets another component write in the same transaction as
// the lines, so its rows exist exactly when the lines do.
//
// InTx runs after the COPY and before the commit. Its errors are isolated from
// the lines: a failing hook is rolled back on its own and the lines still
// commit, unless the failure is transient, in which case the whole batch is
// retried. A defect in a consumer must not stop log ingest.
type ContainerCommitHook interface {
	InTx(ctx context.Context, tx HookTx, lines []StoredContainerLine) error
	AfterCommit(lines []StoredContainerLine)
}

type containerJob struct {
	lines  []StoredContainerLine
	weight int64
	done   chan error
}

// NewContainerPipeline starts the writers. bufferSize is the number of lines
// that may be admitted but not yet committed; flushInterval is how long a
// writer waits for more batches to join the one it holds.
func NewContainerPipeline(pool *pgxpool.Pool, bufferSize, workerCount, batchSize int, flushInterval time.Duration) *ContainerPipeline {
	return newContainerPipeline(&pgContainerStore{pool: pool}, bufferSize, workerCount, batchSize, flushInterval)
}

func newContainerPipeline(store containerStore, bufferSize, workerCount, batchSize int, flushInterval time.Duration) *ContainerPipeline {
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
		flushInterval = DefaultContainerFlushInterval
	}

	p := &ContainerPipeline{
		store:    store,
		sem:      semaphore.NewWeighted(int64(bufferSize)),
		capacity: int64(bufferSize),
		// Every admitted job holds at least one unit of the semaphore, so
		// the channel can never hold more jobs than bufferSize and a send
		// under the read lock never blocks.
		jobs: make(chan *containerJob, bufferSize),
	}

	for i := 0; i < workerCount; i++ {
		w := &containerWorker{id: i, pipeline: p, batchSize: batchSize, flushInterval: flushInterval}
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

// DefaultContainerFlushInterval is how long a writer holds a batch waiting for
// others. Shippers wait for the commit, so this is latency added to every
// batch; it has to stay well under the shipper's send timeout.
const DefaultContainerFlushInterval = 250 * time.Millisecond

// SetCommitHook registers the component that writes alongside the lines. nil
// removes it.
func (p *ContainerPipeline) SetCommitHook(h ContainerCommitHook) {
	if h == nil {
		p.hook.Store(nil)
		return
	}
	p.hook.Store(&containerHookHolder{hook: h})
}

func (p *ContainerPipeline) commitHook() ContainerCommitHook {
	if h := p.hook.Load(); h != nil {
		return h.hook
	}
	return nil
}

// SendBatch admits a batch and waits until it is committed.
//
// A nil return means every line is stored, or was refused as unstorable and
// logged. Any other return means the shipper still owns the batch. When ctx
// ends after admission the batch may still commit; the shipper resends, and the
// duplicate is the price of never losing a line.
func (p *ContainerPipeline) SendBatch(ctx context.Context, entries []ContainerEntry) error {
	if len(entries) == 0 {
		return nil
	}
	if p.closed.Load() {
		return ErrContainerPipelineClosed
	}

	lines := prepareContainerLines(entries)
	weight := int64(len(lines))
	if weight > p.capacity {
		// A single batch larger than the buffer would never be admitted.
		weight = p.capacity
	}
	if err := p.sem.Acquire(ctx, weight); err != nil {
		p.rejected.Add(int64(len(lines)))
		return errors.Join(ErrContainerPipelineFull, err)
	}

	job := &containerJob{lines: lines, weight: weight, done: make(chan error, 1)}
	p.jobsMu.RLock()
	if p.closed.Load() {
		p.jobsMu.RUnlock()
		p.sem.Release(weight)
		return ErrContainerPipelineClosed
	}
	p.jobs <- job
	p.jobsMu.RUnlock()

	p.inFlight.Add(int64(len(lines)))
	p.enqueued.Add(int64(len(lines)))
	p.lastBatchUnix.Store(time.Now().Unix())

	select {
	case err := <-job.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// prepareContainerLines fixes everything a write needs before the first
// attempt, so retries and splits operate on identical rows.
func prepareContainerLines(entries []ContainerEntry) []StoredContainerLine {
	now := time.Now()
	out := make([]StoredContainerLine, 0, len(entries))
	for _, e := range entries {
		if e.ReceivedAt.IsZero() {
			e.ReceivedAt = now
		}
		// JSON lines are parsed into attrs so the panel and the event rules
		// can filter on fields. Only attempted when the line starts like an
		// object.
		if len(e.Attrs) == 0 && len(e.Line) > 1 && e.Line[0] == '{' {
			e.Attrs = parseJSONLine(e.Line)
		}
		// NUL and invalid UTF-8 would fail the COPY for every line in it.
		sanitizeContainerEntry(&e)

		ts := e.Timestamp
		if ts.IsZero() {
			ts = e.ReceivedAt
		}
		out = append(out, StoredContainerLine{
			ID:        uuid.Must(uuid.NewV7()),
			Timestamp: ts,
			Stream:    normalizeStream(e.Stream),
			Entry:     e,
		})
	}
	return out
}

// complete settles a job and returns its admission slot.
func (p *ContainerPipeline) complete(job *containerJob, err error) {
	p.inFlight.Add(-int64(len(job.lines)))
	p.sem.Release(job.weight)
	job.done <- err
}

// UpdateShipperStats records the spool size a shipper reports so the panel can
// show that a host is behind.
func (p *ContainerPipeline) UpdateShipperStats(spoolBytes, spoolOldestUnix int64) {
	p.shipperMu.Lock()
	p.shipperReportedAtUnix = time.Now().Unix()
	p.spoolBytes = spoolBytes
	p.spoolOldestUnix = spoolOldestUnix
	p.shipperMu.Unlock()
}

// IngestStats snapshots health state for the GetIngestStatus RPC. dropped
// counts lines that were refused, either because the pipeline was full (the
// shipper keeps those) or because they could not be stored at all.
func (p *ContainerPipeline) IngestStats(staleAfter time.Duration) (enqueued, dropped int64, queueLen int, lastBatchAt time.Time, containersActive int64, spoolBytes, spoolOldestSeconds int64, degraded bool) {
	enqueued = p.enqueued.Load()
	dropped = p.rejected.Load()
	queueLen = int(p.inFlight.Load())
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
	if staleAfter > 0 && reportedAtUnix > 0 && now-reportedAtUnix > int64(staleAfter.Seconds()) {
		degraded = true
	}
	if spoolBytes > 0 {
		degraded = true
	}
	return
}

// Stop refuses new batches, lets the writers finish what was admitted, and
// returns when every admitted batch has been settled.
func (p *ContainerPipeline) Stop() {
	p.jobsMu.Lock()
	if !p.closed.CompareAndSwap(false, true) {
		p.jobsMu.Unlock()
		return
	}
	close(p.jobs)
	p.jobsMu.Unlock()

	slog.Info("container log pipeline shutting down", "in_flight", p.inFlight.Load())
	p.workerWg.Wait()
	slog.Info("container log pipeline stopped",
		"total_enqueued", p.enqueued.Load(),
		"total_rejected", p.rejected.Load())
}
