package middleware

import (
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"

	"github.com/klauspost/compress/gzip"
)

var gzipWriterPool = sync.Pool{
	New: func() any {
		w, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
		return w
	},
}

// An allow-list, so an unlisted binary type keeps its Content-Length.
var compressibleTypes = map[string]bool{
	"application/json":         true,
	"application/javascript":   true,
	"application/x-javascript": true,
	"application/ecmascript":   true,
	"application/xml":          true,
	"application/x-ndjson":     true,
}

// Parameters such as charset are ignored; an unparsable type is not compressible.
func isCompressibleType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	if strings.HasPrefix(mediaType, "text/") || compressibleTypes[mediaType] {
		return true
	}
	// RFC 6839 structured syntax suffixes: application/problem+json, image/svg+xml.
	return strings.HasSuffix(mediaType, "+json") || strings.HasSuffix(mediaType, "+xml")
}

func shouldCompress(code int, h http.Header) bool {
	switch {
	case code == http.StatusNoContent, code == http.StatusNotModified:
		return false
	case code == http.StatusPartialContent:
		// Content-Range offsets refer to the identity encoding.
		return false
	case h.Get("Content-Encoding") != "":
		return false
	}
	return isCompressibleType(h.Get("Content-Type"))
}

type gzipResponseWriter struct {
	http.ResponseWriter
	writer      *gzip.Writer
	wroteHeader bool
}

func (grw *gzipResponseWriter) Write(b []byte) (int, error) {
	if !grw.wroteHeader {
		grw.WriteHeader(http.StatusOK)
	}
	if grw.writer == nil {
		return grw.ResponseWriter.Write(b)
	}
	return grw.writer.Write(b)
}

func (grw *gzipResponseWriter) WriteHeader(code int) {
	if grw.wroteHeader {
		return
	}
	// Informational responses precede the final one and carry no body.
	if code < http.StatusOK {
		grw.ResponseWriter.WriteHeader(code)
		return
	}
	grw.wroteHeader = true

	h := grw.ResponseWriter.Header()
	if shouldCompress(code, h) {
		gz := gzipWriterPool.Get().(*gzip.Writer)
		gz.Reset(grw.ResponseWriter)
		grw.writer = gz

		h.Del("Content-Length")
		h.Set("Content-Encoding", "gzip")
		h.Add("Vary", "Accept-Encoding")
	}
	grw.ResponseWriter.WriteHeader(code)
}

func (grw *gzipResponseWriter) Flush() {
	if grw.writer != nil {
		grw.writer.Flush()
	}
	if f, ok := grw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (grw *gzipResponseWriter) close() {
	if grw.writer == nil {
		return
	}
	grw.writer.Close()
	gzipWriterPool.Put(grw.writer)
	grw.writer = nil
}

func Gzip(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		// An upgraded connection is a raw stream, not an HTTP body.
		if r.Header.Get("Upgrade") != "" {
			next.ServeHTTP(w, r)
			return
		}

		grw := &gzipResponseWriter{ResponseWriter: w}
		defer grw.close()
		next.ServeHTTP(grw, r)
	})
}
