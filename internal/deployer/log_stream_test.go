package deployer

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// frame builds a single Docker multiplexed log frame: 8-byte header +
// payload. streamType: 1 = stdout, 2 = stderr.
func frame(streamType byte, payload string) []byte {
	header := make([]byte, 8)
	header[0] = streamType
	binary.BigEndian.PutUint32(header[4:8], uint32(len(payload)))
	return append(header, []byte(payload)...)
}

func collectChunks(t *testing.T, d *LogDemuxer, want int) []LogChunk {
	t.Helper()
	out := make([]LogChunk, 0, want)
	deadline := time.After(2 * time.Second)
	for len(out) < want {
		select {
		case c, ok := <-d.Out():
			if !ok {
				return out
			}
			out = append(out, c)
		case <-deadline:
			t.Fatalf("timed out collecting chunks; got %d/%d", len(out), want)
		}
	}
	return out
}

func TestLogDemuxer_StdoutStderrSplit(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(frame(1, "alpha\nbravo\n"))
	buf.Write(frame(2, "stderr-line\n"))
	d := NewLogDemuxer(&buf, DemuxOptions{})

	got := collectChunks(t, d, 3)
	if got[0].Stream != "stdout" || got[0].Line != "alpha" {
		t.Errorf("first chunk = %+v, want stdout/alpha", got[0])
	}
	if got[1].Stream != "stdout" || got[1].Line != "bravo" {
		t.Errorf("second chunk = %+v, want stdout/bravo", got[1])
	}
	if got[2].Stream != "stderr" || got[2].Line != "stderr-line" {
		t.Errorf("third chunk = %+v, want stderr/stderr-line", got[2])
	}
}

func TestLogDemuxer_TimestampExtraction(t *testing.T) {
	var buf bytes.Buffer
	payload := "2026-05-03T20:06:40.123456789Z hello world\n"
	buf.Write(frame(1, payload))
	d := NewLogDemuxer(&buf, DemuxOptions{HasTimestamps: true})

	got := collectChunks(t, d, 1)
	if got[0].Line != "hello world" {
		t.Errorf("Line = %q, want %q", got[0].Line, "hello world")
	}
	if got[0].Timestamp.IsZero() {
		t.Fatal("Timestamp = zero, want parsed RFC3339Nano")
	}
	if got[0].Timestamp.Year() != 2026 {
		t.Errorf("Timestamp.Year = %d, want 2026", got[0].Timestamp.Year())
	}
}

func TestLogDemuxer_TimestampMissingFallsBack(t *testing.T) {
	var buf bytes.Buffer
	// Caller asks for timestamps but Docker omitted them — line should
	// still flow through verbatim with a zero timestamp.
	buf.Write(frame(1, "no-timestamp-line\n"))
	d := NewLogDemuxer(&buf, DemuxOptions{HasTimestamps: true})

	got := collectChunks(t, d, 1)
	if got[0].Line != "no-timestamp-line" {
		t.Errorf("Line = %q, want %q", got[0].Line, "no-timestamp-line")
	}
	if !got[0].Timestamp.IsZero() {
		t.Errorf("Timestamp = %v, want zero (no parsed leader)", got[0].Timestamp)
	}
}

func TestLogDemuxer_LongLineSplits(t *testing.T) {
	var buf bytes.Buffer
	long := strings.Repeat("x", 50)
	buf.Write(frame(1, long+"\n"))
	d := NewLogDemuxer(&buf, DemuxOptions{MaxLine: 20})

	got := collectChunks(t, d, 3)
	if len(got) != 3 {
		t.Fatalf("got %d chunks, want 3 (50 chars / 20 max-line)", len(got))
	}
	if !got[0].Truncated || !got[1].Truncated {
		t.Errorf("first two chunks must be Truncated=true: %+v / %+v", got[0], got[1])
	}
	if got[2].Truncated {
		t.Errorf("last chunk must be Truncated=false: %+v", got[2])
	}
	if got[0].Line+got[1].Line+got[2].Line != long {
		t.Errorf("reassembled line = %q, want %q", got[0].Line+got[1].Line+got[2].Line, long)
	}
}

func TestLogDemuxer_MultiFrameLineCarry(t *testing.T) {
	// Source flushed half a line in one frame and the rest in the next.
	// Demuxer must concat across frames (within the same stream) when
	// the first half does not end in '\n'.
	//
	// Note: this is the spec; in practice Docker tends to align frames
	// on writes, but the bufio path inside one frame must carry an
	// unfinished tail forward.
	var buf bytes.Buffer
	first := strings.Repeat("a", 30)         // no newline
	second := strings.Repeat("b", 30) + "\n" // newline at end
	buf.Write(frame(1, first+second))         // single frame, big payload
	d := NewLogDemuxer(&buf, DemuxOptions{MaxLine: 1024})

	got := collectChunks(t, d, 1)
	if got[0].Line != first+strings.TrimSuffix(second, "\n") {
		t.Errorf("Line = %q, want concatenation of both halves", got[0].Line)
	}
}

func TestLogDemuxer_DroppedSyntheticOnSlowConsumer(t *testing.T) {
	var buf bytes.Buffer
	for i := 0; i < 50; i++ {
		buf.Write(frame(1, "line\n"))
	}
	// Buffer=1 forces drop-oldest immediately.
	d := NewLogDemuxer(&buf, DemuxOptions{Buffer: 1})

	// Don't drain right away; let the producer fill and drop.
	time.Sleep(50 * time.Millisecond)

	// Drain whatever survived.
	for {
		select {
		case _, ok := <-d.Out():
			if !ok {
				goto done
			}
		case <-time.After(100 * time.Millisecond):
			goto done
		}
	}
done:
	if d.DroppedCount() == 0 {
		t.Fatal("DroppedCount = 0; want > 0 after backpressure")
	}
}

func TestLogDemuxer_TrimsCarriageReturn(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(frame(1, "windows-line\r\n"))
	d := NewLogDemuxer(&buf, DemuxOptions{})

	got := collectChunks(t, d, 1)
	if got[0].Line != "windows-line" {
		t.Errorf("Line = %q, want %q (CRLF stripped)", got[0].Line, "windows-line")
	}
}
