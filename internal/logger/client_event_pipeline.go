package logger

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ClientEventPipeline is the thin ingest pipe for browser RUM events,
// parallel to ContainerPipeline. Every dimension the row carries about the
// visitor, including location, is stamped at the edge before it reaches here.
//
// Drop-on-overflow with counters: a browser beacon is best-effort by design,
// and the edge has already replied 204, so a full buffer must never block.
type ClientEventPipeline struct {
	ch       chan ClientEvent
	pool     *pgxpool.Pool
	workerWg sync.WaitGroup
	quit     chan struct{}
	closed   atomic.Bool
	dropped  atomic.Int64
	enqueued atomic.Int64
}

// NewClientEventPipeline starts workers and returns a ready pipeline. Same
// shape as NewContainerPipeline so wiring in cmd/dialog-siem stays symmetric.
func NewClientEventPipeline(pool *pgxpool.Pool, bufferSize, workerCount, batchSize int, flushInterval time.Duration) *ClientEventPipeline {
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

	p := &ClientEventPipeline{
		ch:   make(chan ClientEvent, bufferSize),
		pool: pool,
		quit: make(chan struct{}),
	}

	for i := 0; i < workerCount; i++ {
		w := newClientEventWorker(i, pool, p.ch, batchSize, flushInterval, p.quit)
		p.workerWg.Add(1)
		go func() {
			defer p.workerWg.Done()
			w.run()
		}()
	}

	slog.Info("client event pipeline started",
		"buffer", bufferSize,
		"workers", workerCount,
		"batch", batchSize,
		"flush", flushInterval.String())
	return p
}

// Send enqueues an event; drops on overflow. Location arrives already stamped
// by the edge from Cloudflare, so there is nothing to enrich here.
func (p *ClientEventPipeline) Send(e ClientEvent) {
	if p.closed.Load() {
		return
	}
	if e.ReceivedAt.IsZero() {
		e.ReceivedAt = time.Now()
	}

	// Strip NUL / invalid UTF-8 so a crafted beacon field can't fail the COPY
	// batch (and take unrelated events down with it).
	sanitizeClientEvent(&e)

	select {
	case p.ch <- e:
		p.enqueued.Add(1)
	default:
		p.dropped.Add(1)
		slog.Warn("client event pipeline full, dropping event",
			"dropped_total", p.dropped.Load(),
			"event", e.EventName)
	}
}

// SendBatch enqueues a slice of already-flattened events.
func (p *ClientEventPipeline) SendBatch(events []ClientEvent) {
	for i := range events {
		p.Send(events[i])
	}
}

func (p *ClientEventPipeline) Stop() {
	if !p.closed.CompareAndSwap(false, true) {
		return
	}
	slog.Info("client event pipeline shutting down", "queued", len(p.ch))
	close(p.quit)
	close(p.ch)
	p.workerWg.Wait()
	slog.Info("client event pipeline stopped",
		"total_enqueued", p.enqueued.Load(),
		"total_dropped", p.dropped.Load())
}
