package deployer

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand"
	"strings"
	"testing"
)

// binFrame builds one Docker stream frame: stream(1) + reserved(3) + size(BE32).
func binFrame(stream byte, payload []byte) []byte {
	h := make([]byte, 8)
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:8], uint32(len(payload)))
	return append(h, payload...)
}

// This is the regression test for the corrupted backups. pg_dump -Fc output is
// compressed binary: it carries 0x0A and 0x0D bytes at arbitrary offsets and
// runs of them. The line demuxer deletes exactly those, which is why every
// dump the upgrade flow produced was unrestorable. The stream path must hand
// back the payload unchanged.
func TestCopyDockerFramesPreservesBinaryPayload(t *testing.T) {
	payload := []byte{
		'P', 'G', 'D', 'M', 'P',
		0x00, 0x0A, 0x0A, 0x0D, 0x0A, // runs the demuxer collapses to nothing
		0xFF, 0x00, '\n', '\r', '\n',
		0x1F, 0x8B, 0x08, 0x00, // gzip member header, as a custom dump carries
	}

	var out bytes.Buffer
	stderrTail, err := copyDockerFrames(bytes.NewReader(binFrame(1, payload)), &out, 1024)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if len(stderrTail) != 0 {
		t.Fatalf("unexpected stderr: %q", stderrTail)
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("payload was rewritten:\n got %v\nwant %v", out.Bytes(), payload)
	}
}

// A dump arrives as thousands of frames, and the writer must not reorder or
// lose any of them. Random binary content across many frames is the closest
// cheap analogue of the real stream.
func TestCopyDockerFramesReassemblesManyFrames(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var want bytes.Buffer
	var wire bytes.Buffer
	for i := 0; i < 500; i++ {
		chunk := make([]byte, 1+rng.Intn(3000))
		for j := range chunk {
			// Bias towards newline bytes so the test would fail loudly under
			// any line-oriented handling.
			if rng.Intn(4) == 0 {
				chunk[j] = '\n'
				continue
			}
			chunk[j] = byte(rng.Intn(256))
		}
		want.Write(chunk)
		wire.Write(binFrame(1, chunk))
	}

	var out bytes.Buffer
	if _, err := copyDockerFrames(bytes.NewReader(wire.Bytes()), &out, 1024); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if !bytes.Equal(out.Bytes(), want.Bytes()) {
		t.Fatalf("reassembled stream differs: got %d bytes, want %d", out.Len(), want.Len())
	}
}

func TestCopyDockerFramesSeparatesStderr(t *testing.T) {
	var wire bytes.Buffer
	wire.Write(binFrame(1, []byte{0x00, 0x0A, 0x01}))
	wire.Write(binFrame(2, []byte("pg_dump: error: connection failed")))
	wire.Write(binFrame(1, []byte{0x02}))

	var out bytes.Buffer
	stderrTail, err := copyDockerFrames(bytes.NewReader(wire.Bytes()), &out, 1024)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if !bytes.Equal(out.Bytes(), []byte{0x00, 0x0A, 0x01, 0x02}) {
		t.Fatalf("stdout polluted or reordered: %v", out.Bytes())
	}
	if !strings.Contains(string(stderrTail), "connection failed") {
		t.Fatalf("stderr not captured: %q", stderrTail)
	}
}

// A chatty command must not be able to grow the deployer's heap through the
// stderr tail while its real output streams to disk.
func TestCopyDockerFramesCapsStderrTail(t *testing.T) {
	var wire bytes.Buffer
	wire.Write(binFrame(2, bytes.Repeat([]byte("x"), 10_000)))
	wire.Write(binFrame(1, []byte("ok")))

	var out bytes.Buffer
	stderrTail, err := copyDockerFrames(bytes.NewReader(wire.Bytes()), &out, 100)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if len(stderrTail) != 100 {
		t.Fatalf("stderr tail not capped: got %d bytes", len(stderrTail))
	}
	if out.String() != "ok" {
		t.Fatalf("stdout lost after an oversized stderr frame: %q", out.String())
	}
}

// A connection that dies mid-command must be an error. Silently returning the
// short prefix is how a truncated backup passes for a finished one.
func TestCopyDockerFramesRejectsTruncatedStream(t *testing.T) {
	full := binFrame(1, []byte("0123456789"))

	t.Run("payload cut short", func(t *testing.T) {
		var out bytes.Buffer
		_, err := copyDockerFrames(bytes.NewReader(full[:12]), &out, 1024)
		if err == nil {
			t.Fatal("expected an error for a truncated payload")
		}
	})

	t.Run("header cut short", func(t *testing.T) {
		var out bytes.Buffer
		_, err := copyDockerFrames(bytes.NewReader(append(full, 0x01, 0x00)), &out, 1024)
		if err == nil {
			t.Fatal("expected an error for a truncated header")
		}
	})

	t.Run("clean end on a frame boundary", func(t *testing.T) {
		var out bytes.Buffer
		if _, err := copyDockerFrames(bytes.NewReader(full), &out, 1024); err != nil {
			t.Fatalf("clean stream reported an error: %v", err)
		}
	})
}

// Frames from stdin or an unknown channel are skipped without consuming the
// frames that follow them.
func TestCopyDockerFramesSkipsUnknownStreams(t *testing.T) {
	var wire bytes.Buffer
	wire.Write(binFrame(0, []byte("stdin echo")))
	wire.Write(binFrame(7, []byte("who knows")))
	wire.Write(binFrame(1, []byte{0xAA, 0x0A, 0xBB}))

	var out bytes.Buffer
	if _, err := copyDockerFrames(bytes.NewReader(wire.Bytes()), &out, 1024); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if !bytes.Equal(out.Bytes(), []byte{0xAA, 0x0A, 0xBB}) {
		t.Fatalf("frame after an unknown stream was lost: %v", out.Bytes())
	}
}

// The demuxer is still the right tool for container logs, and this pins the
// difference so nobody "fixes" the binary path by pointing it back at the
// demuxer: the same bytes come out mangled there.
func TestLogDemuxerIsNotByteExactByDesign(t *testing.T) {
	payload := []byte{'a', '\n', '\n', 'b'}
	dem := NewLogDemuxer(bytes.NewReader(binFrame(1, payload)), DemuxOptions{MaxLine: 1 << 20})
	var got bytes.Buffer
	for chunk := range dem.Out() {
		got.WriteString(chunk.Line)
	}
	if bytes.Equal(got.Bytes(), payload) {
		t.Fatal("demuxer preserved the payload; the binary path may no longer need a separate reader")
	}
}

var _ io.Writer = (*limitedWriter)(nil)
