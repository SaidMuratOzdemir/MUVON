package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/klauspost/compress/gzip"
)

var gzipTestBody = []byte(strings.Repeat("muvon gzip middleware test body ", 64))

func serveGzip(t *testing.T, acceptEncoding string, status int, headers map[string]string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	handler := Gzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		if len(body) > 0 {
			w.Write(body)
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if acceptEncoding != "" {
		req.Header.Set("Accept-Encoding", acceptEncoding)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func withLength(contentType string, body []byte) map[string]string {
	return map[string]string{
		"Content-Type":   contentType,
		"Content-Length": strconv.Itoa(len(body)),
	}
}

func gunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("body is not gzip: %v", err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("read gzip body: %v", err)
	}
	return out
}

func TestGzipCompressesTextLikeTypes(t *testing.T) {
	types := []string{
		"text/html; charset=utf-8",
		"text/plain",
		"text/css",
		"text/javascript",
		"application/json",
		"application/json; charset=utf-8",
		"Application/JSON; Charset=UTF-8",
		"application/javascript",
		"application/xml",
		"application/problem+json",
		"application/rss+xml",
		"image/svg+xml",
	}
	for _, ct := range types {
		t.Run(ct, func(t *testing.T) {
			rec := serveGzip(t, "gzip, br", http.StatusOK, withLength(ct, gzipTestBody), gzipTestBody)

			if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
				t.Fatalf("Content-Encoding = %q, want gzip", got)
			}
			if got := rec.Header().Get("Content-Length"); got != "" {
				t.Fatalf("Content-Length = %q, want it removed from a compressed response", got)
			}
			if got := rec.Header().Get("Vary"); got != "Accept-Encoding" {
				t.Fatalf("Vary = %q, want Accept-Encoding", got)
			}
			if got := gunzip(t, rec.Body.Bytes()); !bytes.Equal(got, gzipTestBody) {
				t.Fatalf("decompressed body differs from the original")
			}
		})
	}
}

func TestGzipLeavesOtherTypesUncompressed(t *testing.T) {
	types := []string{
		"application/pdf",
		"image/png",
		"image/jpeg",
		"image/webp",
		"video/mp4",
		"audio/mpeg",
		"application/zip",
		"application/gzip",
		"application/octet-stream",
		"application/wasm",
		"font/woff2",
		"",
		"not a media type;;",
	}
	for _, ct := range types {
		t.Run("type="+ct, func(t *testing.T) {
			headers := withLength(ct, gzipTestBody)
			if ct == "" {
				delete(headers, "Content-Type")
			}
			rec := serveGzip(t, "gzip, br", http.StatusOK, headers, gzipTestBody)
			assertPassedThrough(t, rec)
		})
	}
}

func TestGzipPreservesContentLengthOfUncompressedResponse(t *testing.T) {
	rec := serveGzip(t, "gzip", http.StatusOK, withLength("application/pdf", gzipTestBody), gzipTestBody)

	want := strconv.Itoa(len(gzipTestBody))
	if got := rec.Header().Get("Content-Length"); got != want {
		t.Fatalf("Content-Length = %q, want %q", got, want)
	}
	if got := rec.Header().Get("Vary"); got != "" {
		t.Fatalf("Vary = %q, want none on a response that does not vary", got)
	}
}

// A client that always sends Accept-Encoding: gzip still receives a PDF's Content-Length.
func TestGzipPreservesContentLengthThroughServer(t *testing.T) {
	srv := httptest.NewServer(Gzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Length", strconv.Itoa(len(gzipTestBody)))
		w.Write(gzipTestBody)
	})))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Accept-Encoding", "gzip, br")
	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.ContentLength != int64(len(gzipTestBody)) {
		t.Fatalf("ContentLength = %d, want %d", resp.ContentLength, len(gzipTestBody))
	}
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want none", got)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, gzipTestBody) {
		t.Fatalf("body differs from the original")
	}
}

func TestGzipSkipsAlreadyEncodedResponse(t *testing.T) {
	headers := withLength("text/html", gzipTestBody)
	headers["Content-Encoding"] = "br"
	rec := serveGzip(t, "gzip", http.StatusOK, headers, gzipTestBody)

	if got := rec.Header().Get("Content-Encoding"); got != "br" {
		t.Fatalf("Content-Encoding = %q, want the backend's br untouched", got)
	}
	if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(len(gzipTestBody)) {
		t.Fatalf("Content-Length = %q, want it preserved", got)
	}
	if !bytes.Equal(rec.Body.Bytes(), gzipTestBody) {
		t.Fatalf("body was altered")
	}
}

func TestGzipSkipsPartialContent(t *testing.T) {
	headers := withLength("text/plain", gzipTestBody)
	headers["Content-Range"] = "bytes 0-" + strconv.Itoa(len(gzipTestBody)-1) + "/99999"
	rec := serveGzip(t, "gzip", http.StatusPartialContent, headers, gzipTestBody)
	assertPassedThrough(t, rec)
}

func TestGzipSkipsBodylessStatuses(t *testing.T) {
	for _, code := range []int{http.StatusNoContent, http.StatusNotModified} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			rec := serveGzip(t, "gzip", code, map[string]string{"Content-Type": "text/html"}, nil)
			if got := rec.Header().Get("Content-Encoding"); got != "" {
				t.Fatalf("Content-Encoding = %q, want none", got)
			}
			if rec.Body.Len() != 0 {
				t.Fatalf("body has %d bytes, want none", rec.Body.Len())
			}
		})
	}
}

func TestGzipWithoutAcceptEncodingPassesThrough(t *testing.T) {
	rec := serveGzip(t, "", http.StatusOK, withLength("text/html", gzipTestBody), gzipTestBody)
	assertPassedThrough(t, rec)
}

func assertPassedThrough(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want none", got)
	}
	if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(len(gzipTestBody)) {
		t.Fatalf("Content-Length = %q, want %d preserved", got, len(gzipTestBody))
	}
	if !bytes.Equal(rec.Body.Bytes(), gzipTestBody) {
		t.Fatalf("body was altered: %d bytes, want %d", rec.Body.Len(), len(gzipTestBody))
	}
}
