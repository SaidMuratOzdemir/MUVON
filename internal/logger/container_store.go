package logger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HookTx is the transaction a commit hook writes in.
type HookTx = pgx.Tx

// containerStore writes a set of lines atomically. It is an interface so the
// admission and splitting logic can be tested without a database.
type containerStore interface {
	Write(ctx context.Context, lines []StoredContainerLine, hook ContainerCommitHook) error
}

type pgContainerStore struct {
	pool *pgxpool.Pool
}

var containerLogColumns = []string{
	"id", "timestamp", "received_at", "host_id",
	"container_id", "container_name", "image",
	"project", "component", "release_id", "deployment_id",
	"stream", "line", "truncated", "seq", "attrs",
}

func (s *pgContainerStore) Write(ctx context.Context, lines []StoredContainerLine, hook ContainerCommitHook) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := tx.CopyFrom(ctx,
			pgx.Identifier{"container_logs"},
			containerLogColumns,
			pgx.CopyFromSlice(len(lines), func(i int) ([]any, error) {
				return containerLogRow(lines[i]), nil
			}),
		)
		if err != nil {
			return fmt.Errorf("copy container_logs: %w", err)
		}
		if hook == nil {
			return nil
		}
		return runCommitHook(ctx, tx, hook, lines)
	})
}

// runCommitHook runs the hook under a savepoint so its failure does not take
// the lines with it. Only a transient failure fails the batch, because the
// commit that follows would most likely fail the same way and a retry can
// succeed; anything else is a defect in the consumer and is logged loudly
// instead of turning into a batch the shipper resends forever.
func runCommitHook(ctx context.Context, tx pgx.Tx, hook ContainerCommitHook, lines []StoredContainerLine) error {
	sp, err := tx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("container commit hook savepoint: %w", err)
	}
	if err := hook.InTx(ctx, sp, lines); err != nil {
		_ = sp.Rollback(ctx)
		if isTransientDBError(err) {
			return fmt.Errorf("container commit hook: %w", err)
		}
		slog.Error("container commit hook failed; lines stored without its rows",
			"rows", len(lines), "error", err)
		return nil
	}
	return sp.Commit(ctx)
}

func containerLogRow(l StoredContainerLine) []any {
	e := l.Entry
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
	return []any{
		l.ID,
		l.Timestamp,
		e.ReceivedAt,
		hostID,
		e.ContainerID,
		e.ContainerName,
		nilIfEmpty(e.Image),
		nilIfEmpty(e.Project),
		nilIfEmpty(e.Component),
		nilIfEmpty(e.ReleaseID),
		deploymentID,
		l.Stream,
		e.Line,
		e.Truncated,
		e.Seq,
		attrs,
	}
}

// isPermanentWriteError reports an error that the same rows will hit again:
// a data exception (class 22) or an integrity violation (class 23). Everything
// else, a lost connection or a missing table included, is worth retrying later
// rather than discarding rows over.
func isPermanentWriteError(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || len(pgErr.Code) < 2 {
		return false
	}
	switch pgErr.Code[:2] {
	case "22", "23":
		return true
	}
	return false
}

// isTransientDBError reports a failure a retry can plausibly outlive.
func isTransientDBError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	if pgconn.Timeout(err) || pgconn.SafeToRetry(err) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && len(pgErr.Code) >= 2 {
		switch pgErr.Code[:2] {
		case "08", "40", "53", "57", "58":
			return true
		}
	}
	return false
}
