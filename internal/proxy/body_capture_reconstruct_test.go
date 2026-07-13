package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newBodyReq(t *testing.T, body []byte, contentType string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, "http://example.com/sign", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	r.Header.Set("Content-Type", contentType)
	r.ContentLength = int64(len(body))
	return r
}

func readBody(t *testing.T, r *http.Request) []byte {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read reconstructed body: %v", err)
	}
	return b
}

// The forwarded body must be byte-for-byte identical to the client body for
// every size, including at and just past the capture cap. Regression for the
// off-by-one that dropped the byte at offset maxSize on bodies > maxSize.
func TestCaptureRequestBody_ForwardedBodyIntact(t *testing.T) {
	const maxSize = 64
	sizes := []int{0, 1, maxSize - 1, maxSize, maxSize + 1, maxSize + 2, 4 * maxSize}

	for _, n := range sizes {
		body := make([]byte, n)
		for i := range body {
			body[i] = byte('A' + i%26)
		}

		r := newBodyReq(t, body, "application/json")
		r2, cap, err := CaptureRequestBody(r, maxSize)
		if err != nil {
			t.Fatalf("CaptureRequestBody: %v", err)
		}

		got := readBody(t, r2)
		if !bytes.Equal(got, body) {
			t.Errorf("size=%d: forwarded body altered: got %d bytes, want %d", n, len(got), len(body))
		}
		if r2.ContentLength != int64(len(body)) {
			t.Errorf("size=%d: ContentLength=%d, want %d", n, r2.ContentLength, len(body))
		}
		if cap.Size != len(body) {
			t.Errorf("size=%d: CapturedBody.Size=%d, want %d", n, cap.Size, len(body))
		}

		wantTrunc := n > maxSize
		if cap.Truncated != wantTrunc {
			t.Errorf("size=%d: Truncated=%v, want %v", n, cap.Truncated, wantTrunc)
		}
		wantCap := n
		if wantCap > maxSize {
			wantCap = maxSize
		}
		if len(cap.Data) != wantCap {
			t.Errorf("size=%d: captured len=%d, want %d", n, len(cap.Data), wantCap)
		}
		if !bytes.Equal(cap.Data, body[:wantCap]) {
			t.Errorf("size=%d: captured prefix mismatch", n)
		}
	}
}

// Production default cap is 65536; a body just over it must survive intact.
func TestCaptureRequestBody_64KiBBoundary(t *testing.T) {
	const maxSize = 65536
	body := make([]byte, maxSize+1)
	for i := range body {
		body[i] = byte(i)
	}

	r := newBodyReq(t, body, "application/json")
	r2, cap, err := CaptureRequestBody(r, maxSize)
	if err != nil {
		t.Fatalf("CaptureRequestBody: %v", err)
	}

	got := readBody(t, r2)
	if len(got) != maxSize+1 {
		t.Fatalf("forwarded body len=%d, want %d", len(got), maxSize+1)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("forwarded body corrupted at 64KiB boundary")
	}
	if !cap.Truncated || len(cap.Data) != maxSize {
		t.Fatalf("captured: truncated=%v len=%d, want true/%d", cap.Truncated, len(cap.Data), maxSize)
	}
}

// Skipped content types must pass the body through untouched and unread.
func TestCaptureRequestBody_SkipContentType(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 100000)
	r := newBodyReq(t, body, "multipart/form-data; boundary=z")
	r2, cap, err := CaptureRequestBody(r, 64)
	if err != nil {
		t.Fatalf("CaptureRequestBody: %v", err)
	}

	got := readBody(t, r2)
	if !bytes.Equal(got, body) {
		t.Fatalf("skipped body altered")
	}
	if len(cap.Data) != 0 {
		t.Fatalf("skipped body should not be captured, got %d bytes", len(cap.Data))
	}
	if cap.Size != len(body) {
		t.Fatalf("skipped Size=%d, want %d", cap.Size, len(body))
	}
}

// ResponseCapture must set Truncated when the capture buffer fills exactly and
// more bytes follow, while always writing the full body to the client.
func TestResponseCapture_TruncatedFlagOnExactFill(t *testing.T) {
	const maxSize = 64
	rec := httptest.NewRecorder()
	rc := NewResponseCapture(rec, maxSize, false)

	first := bytes.Repeat([]byte("a"), maxSize) // fills the buffer exactly
	more := bytes.Repeat([]byte("b"), 10)       // must be dropped from capture
	if _, err := rc.Write(first); err != nil {
		t.Fatalf("write first: %v", err)
	}
	if _, err := rc.Write(more); err != nil {
		t.Fatalf("write more: %v", err)
	}

	cap := rc.CapturedBody()
	if !cap.Truncated {
		t.Errorf("Truncated=false, want true after exact-fill + extra write")
	}
	if len(cap.Data) != maxSize {
		t.Errorf("captured len=%d, want %d", len(cap.Data), maxSize)
	}
	if cap.Size != maxSize+10 {
		t.Errorf("total Size=%d, want %d", cap.Size, maxSize+10)
	}
	if got := rec.Body.Len(); got != maxSize+10 {
		t.Errorf("client body len=%d, want %d (client copy must be complete)", got, maxSize+10)
	}
}

// A response under the cap must not be marked truncated.
func TestResponseCapture_NotTruncatedUnderCap(t *testing.T) {
	rec := httptest.NewRecorder()
	rc := NewResponseCapture(rec, 64, false)
	if _, err := rc.Write(bytes.Repeat([]byte("x"), 64)); err != nil {
		t.Fatalf("write: %v", err)
	}
	cap := rc.CapturedBody()
	if cap.Truncated {
		t.Errorf("Truncated=true, want false for body == maxSize")
	}
	if len(cap.Data) != 64 || cap.Size != 64 {
		t.Errorf("captured=%d size=%d, want 64/64", len(cap.Data), cap.Size)
	}
}
