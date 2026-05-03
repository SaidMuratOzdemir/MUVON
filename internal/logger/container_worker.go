package logger

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type containerWorker struct {
	id       int
	pool     *pgxpool.Pool
	entries  <-chan ContainerEntry
	batchSz  int
	flushInt time.Duration
	quit     <-chan struct{}
}

func newContainerWorker(id int, pool *pgxpool.Pool, ch <-chan ContainerEntry, batchSize int, flushInterval time.Duration, quit <-chan struct{}) *containerWorker {
	return &containerWorker{
		id:       id,
		pool:     pool,
		entries:  ch,
		batchSz:  batchSize,
		flushInt: flushInterval,
		quit:     quit,
	}
}

func (w *containerWorker) run() {
	slog.Info("container log worker started", "worker", w.id)
	batch := make([]ContainerEntry, 0, w.batchSz)
	ticker := time.NewTicker(w.flushInt)
	defer ticker.Stop()

	for {
		select {
		case entry, ok := <-w.entries:
			if !ok {
				if len(batch) > 0 {
					w.flush(batch)
				}
				slog.Info("container log worker stopped", "worker", w.id)
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
			drain := true
			for drain {
				select {
				case entry, ok := <-w.entries:
					if !ok {
						drain = false
						break
					}
					batch = append(batch, entry)
				default:
					drain = false
				}
			}
			if len(batch) > 0 {
				w.flush(batch)
			}
			slog.Info("container log worker drained and stopped", "worker", w.id)
			return
		}
	}
}

func (w *containerWorker) flush(batch []ContainerEntry) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rows := make([][]any, 0, len(batch))
	for _, e := range batch {
		stream := strings.ToLower(strings.TrimSpace(e.Stream))
		if stream != "stdout" && stream != "stderr" {
			// Default unknown to stdout — never drop a row over a
			// missing stream tag; the source binary can still be
			// debugged from the line itself.
			stream = "stdout"
		}
		ts := e.Timestamp
		if ts.IsZero() {
			ts = e.ReceivedAt
		}
		if ts.IsZero() {
			ts = time.Now()
		}
		var deploymentID *uuid.UUID
		if e.DeploymentID != "" {
			if u, err := uuid.Parse(e.DeploymentID); err == nil {
				deploymentID = &u
			}
		}
		var attrs json.RawMessage
		if v := e.AttrsJSON(); len(v) > 0 {
			attrs = v
		}
		hostID := e.HostID
		if hostID == "" {
			hostID = "central"
		}
		rows = append(rows, []any{
			uuid.Must(uuid.NewV7()),
			ts,
			e.ReceivedAt,
			hostID,
			e.ContainerID,
			e.ContainerName,
			nilIfEmpty(e.Image),
			nilIfEmpty(e.Project),
			nilIfEmpty(e.Component),
			nilIfEmpty(e.ReleaseID),
			deploymentID,
			stream,
			e.Line,
			e.Truncated,
			e.Seq,
			attrs,
		})
	}

	_, err := w.pool.CopyFrom(ctx,
		pgx.Identifier{"container_logs"},
		[]string{
			"id", "timestamp", "received_at", "host_id",
			"container_id", "container_name", "image",
			"project", "component", "release_id", "deployment_id",
			"stream", "line", "truncated", "seq", "attrs",
		},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		slog.Error("container log flush: COPY container_logs",
			"error", err,
			"worker", w.id,
			"rows", len(rows))
		return
	}
	slog.Debug("container log flush complete", "worker", w.id, "rows", len(rows))
}

// parseJSONLine inspects a single log line and, when it looks like a
// top-level JSON object, returns a flat string map of its top-level
// fields. Nested values are stringified — the goal is to enable the
// admin UI's `attrs.level=ERROR`-style filter, not to faithfully
// reconstruct the original tree.
//
// Returns nil for any parse failure, including non-object JSON. nil
// keeps the column NULL so the partial GIN index stays sparse.
func parseJSONLine(line string) map[string]string {
	if len(line) < 2 {
		return nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil
	}
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		// Trim surrounding quotes for string values; cheap and avoids
		// double-encoding when an admin filters on attrs.level=ERROR.
		s := string(v)
		if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
			var unquoted string
			if err := json.Unmarshal(v, &unquoted); err == nil {
				s = unquoted
			}
		}
		// Cap the value to keep the JSONB index manageable.
		if len(s) > 1024 {
			s = s[:1024]
		}
		out[k] = s
	}
	return out
}
