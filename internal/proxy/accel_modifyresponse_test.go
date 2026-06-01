package proxy

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"muvon/internal/db"
)

// A misbehaving backend declares a body via Content-Length on an X-Accel-Redirect
// response but sends none. The edge serves the file itself, so it must discard the
// upstream body and never block waiting for the phantom bytes.
func TestModifyResponse_XAccelDiscardsPhantomBody(t *testing.T) {
	root := "/srv/media"
	mr := modifyResponse(db.Route{AccelRoot: &root})
	if mr == nil {
		t.Fatal("modifyResponse must return a hook when AccelRoot is set")
	}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Accel-Redirect": {"/documents/x.jpeg"},
			"Content-Length":   {"408959"}, // backend lies: declares 408959 bytes...
		},
		ContentLength: 408959,
		Body:          io.NopCloser(strings.NewReader("")), // ...but sends none (phantom)
	}
	if err := mr(resp); err != nil {
		t.Fatalf("modifyResponse err: %v", err)
	}
	if resp.Header.Get("X-Accel-Redirect") == "" {
		t.Fatal("X-Accel-Redirect must be preserved so the accel writer serves the file")
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		t.Fatalf("phantom Content-Length must be removed, got %q", cl)
	}
	if resp.ContentLength != 0 {
		t.Fatalf("ContentLength must be 0, got %d", resp.ContentLength)
	}
	if n, _ := io.Copy(io.Discard, resp.Body); n != 0 {
		t.Fatalf("upstream body must be discarded so the proxy copy can't block, got %d bytes", n)
	}
}

// On an accel route, a normal (non-X-Accel) response must pass through untouched.
func TestModifyResponse_AccelRouteNonXAccelUntouched(t *testing.T) {
	root := "/srv/media"
	mr := modifyResponse(db.Route{AccelRoot: &root})
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Length": {"5"}},
		ContentLength: 5,
		Body:          io.NopCloser(strings.NewReader("hello")),
	}
	if err := mr(resp); err != nil {
		t.Fatalf("err: %v", err)
	}
	if resp.Header.Get("Content-Length") != "5" {
		t.Fatal("normal response on an accel route must keep its Content-Length")
	}
	if n, _ := io.Copy(io.Discard, resp.Body); n != 5 {
		t.Fatalf("normal response body must be intact, got %d", n)
	}
}

// A plain route (no headers, no error pages, no accel) needs no ModifyResponse hook.
func TestModifyResponse_PlainRouteNoHook(t *testing.T) {
	if mr := modifyResponse(db.Route{}); mr != nil {
		t.Fatal("plain route should have no ModifyResponse hook")
	}
}
