package logger

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type worker struct {
	id       int
	pool     *pgxpool.Pool
	entries  <-chan Entry
	batchSz  int
	flushInt time.Duration
	quit     <-chan struct{}
}

func newWorker(id int, pool *pgxpool.Pool, ch <-chan Entry, batchSize int, flushInterval time.Duration, quit <-chan struct{}) *worker {
	return &worker{
		id:       id,
		pool:     pool,
		entries:  ch,
		batchSz:  batchSize,
		flushInt: flushInterval,
		quit:     quit,
	}
}

func (w *worker) run() {
	slog.Info("log worker started", "worker", w.id)
	batch := make([]Entry, 0, w.batchSz)
	ticker := time.NewTicker(w.flushInt)
	defer ticker.Stop()

	for {
		select {
		case entry, ok := <-w.entries:
			if !ok {
				if len(batch) > 0 {
					w.flush(batch)
				}
				slog.Info("log worker stopped", "worker", w.id)
				return
			}
			batch = append(batch, entry)
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
			for {
				select {
				case entry, ok := <-w.entries:
					if !ok {
						break
					}
					batch = append(batch, entry)
				default:
					goto done
				}
			}
		done:
			if len(batch) > 0 {
				w.flush(batch)
			}
			slog.Info("log worker drained and stopped", "worker", w.id)
			return
		}
	}
}

func (w *worker) flush(batch []Entry) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tx, err := w.pool.Begin(ctx)
	if err != nil {
		slog.Error("log flush: begin tx", "error", err, "worker", w.id)
		return
	}
	defer tx.Rollback(ctx)

	// Generate UUIDv7 IDs for each log entry up front so we can link bodies
	logIDs := make([]uuid.UUID, len(batch))
	for i := range batch {
		logIDs[i] = uuid.Must(uuid.NewV7())
	}

	logRows := make([][]any, 0, len(batch))
	for i, e := range batch {
		logRows = append(logRows, []any{
			logIDs[i],
			e.Timestamp, e.Host, e.ClientIP, e.Method, e.Path,
			nilIfEmpty(e.QueryString),
			e.RequestHeadersJSON(),
			e.ResponseStatus,
			e.ResponseHeadersJSON(),
			nilIfZero(e.ResponseTimeMs),
			nilIfZero(e.RequestSize),
			nilIfZero(e.ResponseSize),
			nilIfEmpty(e.UserAgent),
			nilIfEmpty(e.Error),
			e.WafBlocked,
			nilIfEmpty(e.WafBlockReason),
			nilIfZero(e.WafScore),
			nilIfEmpty(e.WafAction),
			e.UserIdentity.JSON(),
			nilIfEmpty(e.Country),
			nilIfEmpty(e.City),
			nilIfEmpty(e.RawJWT),
		})
	}

	copyCount, err := tx.CopyFrom(ctx,
		pgx.Identifier{"http_logs"},
		[]string{"id", "timestamp", "host", "client_ip", "method", "path", "query_string",
			"request_headers", "response_status", "response_headers", "response_time_ms",
			"request_size", "response_size", "user_agent", "error", "waf_blocked", "waf_block_reason",
			"waf_score", "waf_action", "user_identity", "country", "city", "raw_jwt"},
		pgx.CopyFromRows(logRows),
	)
	if err != nil {
		slog.Error("log flush: COPY http_logs", "error", err, "worker", w.id)
		return
	}

	// Insert bodies for entries that have them, using the pre-generated UUIDs
	bodyRows := make([][]any, 0)
	for i, e := range batch {
		if len(e.RequestBody) == 0 && len(e.ResponseBody) == 0 {
			continue
		}
		var reqBody, respBody *string
		if len(e.RequestBody) > 0 {
			s := string(e.RequestBody)
			reqBody = &s
		}
		if len(e.ResponseBody) > 0 {
			s := string(e.ResponseBody)
			respBody = &s
		}
		bodyRows = append(bodyRows, []any{
			logIDs[i], e.Timestamp, reqBody, respBody,
			e.IsRequestTruncated, e.IsResponseTruncated,
		})
	}

	if len(bodyRows) > 0 {
		_, err = tx.CopyFrom(ctx,
			pgx.Identifier{"http_log_bodies"},
			[]string{"log_id", "timestamp", "request_body", "response_body",
				"is_request_truncated", "is_response_truncated"},
			pgx.CopyFromRows(bodyRows),
		)
		if err != nil {
			slog.Error("log flush: COPY http_log_bodies", "error", err, "worker", w.id)
			return
		}
	}

	if err := tx.Commit(ctx); err != nil {
		slog.Error("log flush: commit", "error", err, "worker", w.id)
		return
	}

	slog.Debug("log flush complete", "worker", w.id, "logs", copyCount, "bodies", len(bodyRows))
}
