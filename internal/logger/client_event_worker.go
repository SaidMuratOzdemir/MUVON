package logger

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type clientEventWorker struct {
	id       int
	pool     *pgxpool.Pool
	events   <-chan ClientEvent
	batchSz  int
	flushInt time.Duration
	quit     <-chan struct{}
}

func newClientEventWorker(id int, pool *pgxpool.Pool, ch <-chan ClientEvent, batchSize int, flushInterval time.Duration, quit <-chan struct{}) *clientEventWorker {
	return &clientEventWorker{
		id:       id,
		pool:     pool,
		events:   ch,
		batchSz:  batchSize,
		flushInt: flushInterval,
		quit:     quit,
	}
}

func (w *clientEventWorker) run() {
	slog.Info("client event worker started", "worker", w.id)
	batch := make([]ClientEvent, 0, w.batchSz)
	ticker := time.NewTicker(w.flushInt)
	defer ticker.Stop()

	for {
		select {
		case e, ok := <-w.events:
			if !ok {
				if len(batch) > 0 {
					w.flush(batch)
				}
				slog.Info("client event worker stopped", "worker", w.id)
				return
			}
			batch = append(batch, e)
			if len(batch) >= w.batchSz {
				w.flush(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				w.flush(batch)
				batch = batch[:0]
			}
		case <-w.quit:
			drain := true
			for drain {
				select {
				case e, ok := <-w.events:
					if !ok {
						drain = false
						break
					}
					batch = append(batch, e)
				default:
					drain = false
				}
			}
			if len(batch) > 0 {
				w.flush(batch)
			}
			slog.Info("client event worker drained and stopped", "worker", w.id)
			return
		}
	}
}

func (w *clientEventWorker) flush(batch []ClientEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rows := make([][]any, 0, len(batch))
	for _, e := range batch {
		ts := e.ReceivedAt
		if ts.IsZero() {
			ts = time.Now()
		}
		var clientTS *time.Time
		if !e.ClientTS.IsZero() {
			t := e.ClientTS
			clientTS = &t
		}
		hostID := e.HostID
		if hostID == "" {
			hostID = "central"
		}
		rows = append(rows, []any{
			uuid.Must(uuid.NewV7()),
			ts,
			clientTS,
			e.App,
			nilIfEmpty(e.Release),
			hostID,
			nilIfEmpty(e.Host),
			e.SessionID,
			nilIfEmpty(e.ViewID),
			nilIfEmpty(e.Route),
			nilIfEmpty(e.URLPath),
			nilIfEmpty(e.TraceID),
			nilIfEmpty(e.SpanID),
			e.EventName,
			e.ClientIP,
			nilIfEmpty(e.Country),
			nilIfEmpty(e.City),
			nilIfEmpty(e.UserAgent),
			e.AttrsJSON(),
		})
	}

	_, err := w.pool.CopyFrom(ctx,
		pgx.Identifier{"client_events"},
		[]string{
			"id", "time", "client_ts", "app", "release", "host_id", "host",
			"session_id", "view_id", "route", "url_path", "trace_id", "span_id",
			"event_name", "client_ip", "country", "city", "user_agent", "attrs",
		},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		slog.Error("client event flush: COPY client_events",
			"error", err,
			"worker", w.id,
			"rows", len(rows))
		return
	}
	slog.Debug("client event flush complete", "worker", w.id, "rows", len(rows))
}
