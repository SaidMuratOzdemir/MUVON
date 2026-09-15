package logger

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"
)

// containerWriteAttempts bounds retries of a transient failure inside one
// writer. Past it the batch goes back to the shipper, which owns the longer
// retry through its spool.
const containerWriteAttempts = 3

// containerWriteTimeout bounds one write attempt.
const containerWriteTimeout = 30 * time.Second

type containerWorker struct {
	id            int
	pipeline      *ContainerPipeline
	batchSize     int
	flushInterval time.Duration
}

// run takes one batch, lets others join it until the size or the interval is
// reached, and writes them together. It returns once the jobs channel is
// closed and drained.
func (w *containerWorker) run() {
	p := w.pipeline
	for {
		first, ok := <-p.jobs
		if !ok {
			return
		}
		pending := []*containerJob{first}
		n := len(first.lines)
		if n < w.batchSize {
			timer := time.NewTimer(w.flushInterval)
		collect:
			for n < w.batchSize {
				select {
				case j, ok := <-p.jobs:
					if !ok {
						break collect
					}
					pending = append(pending, j)
					n += len(j.lines)
				case <-timer.C:
					break collect
				}
			}
			timer.Stop()
		}
		w.commit(pending)
	}
}

// commit writes jobs together and settles each one.
//
// A permanent error means some row cannot be stored. Jobs are split first, so
// one bad line only delays the batches it shares a write with; inside a single
// job the lines are split until the unstorable ones are isolated and refused.
// A transient error is handed back to every job in the write.
func (w *containerWorker) commit(jobs []*containerJob) {
	p := w.pipeline
	lines := jobs[0].lines
	if len(jobs) > 1 {
		total := 0
		for _, j := range jobs {
			total += len(j.lines)
		}
		lines = make([]StoredContainerLine, 0, total)
		for _, j := range jobs {
			lines = append(lines, j.lines...)
		}
	}

	err := w.writeWithRetry(lines)
	switch {
	case err == nil:
		for _, j := range jobs {
			p.complete(j, nil)
		}
	case !isPermanentWriteError(err):
		for _, j := range jobs {
			p.complete(j, err)
		}
	case len(jobs) > 1:
		mid := len(jobs) / 2
		w.commit(jobs[:mid])
		w.commit(jobs[mid:])
	default:
		p.complete(jobs[0], w.writeSplitting(jobs[0].lines))
	}
}

// writeSplitting isolates unstorable lines by halving. A line that cannot be
// stored on its own is refused and logged, which is the one case where a line
// is not kept: resending it would fail the same way forever and hold every line
// behind it in the shipper's spool.
func (w *containerWorker) writeSplitting(lines []StoredContainerLine) error {
	err := w.writeWithRetry(lines)
	if err == nil || !isPermanentWriteError(err) {
		return err
	}
	if len(lines) == 1 {
		l := lines[0]
		w.pipeline.rejected.Add(1)
		slog.Error("container log line refused: it cannot be stored",
			"worker", w.id,
			"container", l.Entry.ContainerName,
			"timestamp", l.Timestamp,
			"line_bytes", len(l.Entry.Line),
			"error", err)
		return nil
	}
	mid := len(lines) / 2
	if err := w.writeSplitting(lines[:mid]); err != nil {
		return err
	}
	return w.writeSplitting(lines[mid:])
}

func (w *containerWorker) writeWithRetry(lines []StoredContainerLine) error {
	p := w.pipeline
	// One hook for the whole write, so the rows it wrote in the transaction
	// and the AfterCommit call belong to the same consumer.
	hook := p.commitHook()
	var err error
	for attempt := 1; attempt <= containerWriteAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), containerWriteTimeout)
		err = p.store.Write(ctx, lines, hook)
		cancel()
		if err == nil {
			if hook != nil {
				hook.AfterCommit(lines)
			}
			return nil
		}
		if isPermanentWriteError(err) {
			return err
		}
		if attempt < containerWriteAttempts {
			time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
		}
	}
	slog.Error("container log write failed; batch returned to the shipper",
		"worker", w.id,
		"rows", len(lines),
		"attempts", containerWriteAttempts,
		"error", err)
	return err
}

func normalizeStream(s string) string {
	stream := strings.ToLower(strings.TrimSpace(s))
	if stream != "stdout" && stream != "stderr" {
		// An unknown tag is stored as stdout rather than refusing the row;
		// the line itself still says what it is.
		return "stdout"
	}
	return stream
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
