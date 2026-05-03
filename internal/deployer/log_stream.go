package deployer

import (
	"bufio"
	"encoding/binary"
	"io"
	"strings"
	"sync/atomic"
	"time"
)

// Docker's /containers/{id}/logs returns a multiplexed stream. Each
// frame begins with an 8-byte header:
//
//   [STREAM_TYPE, 0, 0, 0, FRAME_SIZE_BIG_ENDIAN_UINT32]
//
// STREAM_TYPE: 0 = stdin (unused), 1 = stdout, 2 = stderr.
//
// When `timestamps=true`, each frame's payload starts with an RFC3339Nano
// timestamp, then a single space, then the line (which itself may not
// contain a newline if the source did not write one).
//
// LogDemuxer turns that into a sequence of LogChunk records with the
// stream + ts + line + truncated flag set, suitable for shipping over
// gRPC (deployer → admin live tail) or batched into the SIEM.

// LogChunk is one logical record produced by the demuxer.
type LogChunk struct {
	Timestamp time.Time // zero when the source did not request timestamps
	Stream    string    // "stdout" | "stderr"
	Line      string
	Truncated bool // true when source line exceeded MaxLine and was split
	Seq       int64
}

// DemuxOptions tunes the demuxer. Zero values give safe defaults:
//   - MaxLine = 16 KiB
//   - Buffer = 1024 chunks
type DemuxOptions struct {
	// MaxLine is the maximum length of a single emitted line. Source
	// lines longer than this are split, with each fragment marked
	// Truncated=true except the last (which carries the trailing
	// newline). Default 16384.
	MaxLine int
	// Buffer is the channel capacity. Default 1024. The demuxer drops
	// older lines under backpressure (see DroppedCount).
	Buffer int
	// HasTimestamps: if true, the first whitespace-separated token of
	// each frame's payload is parsed as RFC3339Nano. Mismatched leaders
	// fall through verbatim with a zero timestamp.
	HasTimestamps bool
}

// LogDemuxer reads Docker's multiplexed log stream and emits LogChunks.
// Safe for one reader; the goroutine is owned by the demuxer until the
// underlying reader closes or the consumer cancels.
type LogDemuxer struct {
	r       io.Reader
	opts    DemuxOptions
	out     chan LogChunk
	dropped atomic.Int64
	seq     atomic.Int64
}

// NewLogDemuxer wraps r and starts the read goroutine. r must be the
// raw response body from ContainerLogs. Reads are buffered internally;
// don't wrap r in another bufio.Reader.
func NewLogDemuxer(r io.Reader, opts DemuxOptions) *LogDemuxer {
	if opts.MaxLine <= 0 {
		opts.MaxLine = 16 * 1024
	}
	if opts.Buffer <= 0 {
		opts.Buffer = 1024
	}
	d := &LogDemuxer{
		r:    r,
		opts: opts,
		out:  make(chan LogChunk, opts.Buffer),
	}
	go d.run()
	return d
}

// Out is the read side of the demuxer. Close-on-EOF semantics: when the
// upstream Docker reader returns io.EOF (or any error), the channel is
// closed. Slow consumers see drop-oldest with the count surfaced via
// DroppedCount; older lines lose synthesized "[muvon] dropped N lines"
// markers reconstructed by the gRPC bridge so the wire format stays
// uniform.
func (d *LogDemuxer) Out() <-chan LogChunk { return d.out }

// DroppedCount returns the cumulative number of LogChunks the demuxer
// dropped because the consumer was slow.
func (d *LogDemuxer) DroppedCount() int64 { return d.dropped.Load() }

func (d *LogDemuxer) run() {
	defer close(d.out)
	br := bufio.NewReaderSize(d.r, 64*1024)
	header := make([]byte, 8)
	for {
		// Header: stream(1) + reserved(3) + size(uint32 BE).
		if _, err := io.ReadFull(br, header); err != nil {
			return
		}
		streamByte := header[0]
		size := binary.BigEndian.Uint32(header[4:8])
		if size == 0 {
			continue
		}
		var stream string
		switch streamByte {
		case 1:
			stream = "stdout"
		case 2:
			stream = "stderr"
		default:
			// Frame from stdin or an unknown channel; consume and skip.
			if _, err := io.CopyN(io.Discard, br, int64(size)); err != nil {
				return
			}
			continue
		}

		// Read the payload. Frames can be larger than MaxLine, in which
		// case we split into multiple chunks; we also split on embedded
		// newlines because the source can flush several lines in a
		// single write.
		remaining := int64(size)
		var carry []byte // partial-line buffer carried forward when chunk ends mid-line
		for remaining > 0 {
			toRead := remaining
			if toRead > 32*1024 {
				toRead = 32 * 1024
			}
			buf := make([]byte, toRead)
			n, err := io.ReadFull(br, buf)
			if err != nil {
				return
			}
			remaining -= int64(n)

			// Concat carry + buf, then split on '\n' to emit lines.
			data := buf[:n]
			if len(carry) > 0 {
				combined := make([]byte, 0, len(carry)+len(data))
				combined = append(combined, carry...)
				combined = append(combined, data...)
				data = combined
				carry = nil
			}

			start := 0
			for i := 0; i < len(data); i++ {
				if data[i] != '\n' {
					continue
				}
				line := data[start:i]
				d.emitLine(stream, line)
				start = i + 1
			}
			// Anything after the last newline is an unfinished line —
			// carry it into the next chunk read or, if this is the
			// last chunk, emit it on stream end.
			if start < len(data) {
				carry = append(carry, data[start:]...)
			}
		}
		if len(carry) > 0 {
			d.emitLine(stream, carry)
		}
	}
}

// emitLine handles per-line truncation and timestamp extraction, then
// pushes onto the channel with drop-oldest backpressure.
func (d *LogDemuxer) emitLine(stream string, line []byte) {
	// Strip trailing CR (some sources emit CRLF) and normalise.
	line = trimTrailingCR(line)
	if len(line) == 0 {
		return
	}

	var ts time.Time
	text := string(line)
	if d.opts.HasTimestamps {
		// Format: "2026-05-03T20:06:40.269123Z message ..."
		if idx := strings.IndexByte(text, ' '); idx > 0 {
			if t, err := time.Parse(time.RFC3339Nano, text[:idx]); err == nil {
				ts = t
				text = text[idx+1:]
			}
		}
	}

	maxLine := d.opts.MaxLine
	if len(text) <= maxLine {
		d.push(LogChunk{
			Timestamp: ts,
			Stream:    stream,
			Line:      text,
			Truncated: false,
			Seq:       d.seq.Add(1),
		})
		return
	}

	// Split: emit MaxLine-sized fragments with Truncated=true, then a
	// final tail with Truncated=false. This preserves a clean "last
	// fragment carries the EOL" contract for downstream consumers.
	for i := 0; i < len(text); i += maxLine {
		end := i + maxLine
		isLast := false
		if end >= len(text) {
			end = len(text)
			isLast = true
		}
		d.push(LogChunk{
			Timestamp: ts,
			Stream:    stream,
			Line:      text[i:end],
			Truncated: !isLast,
			Seq:       d.seq.Add(1),
		})
	}
}

func (d *LogDemuxer) push(c LogChunk) {
	select {
	case d.out <- c:
	default:
		// Drop-oldest: pull one off and try again. If the consumer is
		// already gone (channel still full), increment dropped and
		// continue — the caller surfaces the count via a synthetic
		// marker.
		select {
		case <-d.out:
		default:
		}
		d.dropped.Add(1)
		select {
		case d.out <- c:
		default:
			// Even after the drop the channel is full; bump dropped
			// and lose this chunk too.
			d.dropped.Add(1)
		}
	}
}

func trimTrailingCR(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
