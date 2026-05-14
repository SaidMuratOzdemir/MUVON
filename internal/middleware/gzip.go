package middleware

import (
	"io"
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

type gzipResponseWriter struct {
	http.ResponseWriter
	writer      *gzip.Writer
	wroteHeader bool
}

func (grw *gzipResponseWriter) Write(b []byte) (int, error) {
	if !grw.wroteHeader {
		grw.WriteHeader(http.StatusOK)
	}
	return grw.writer.Write(b)
}

func (grw *gzipResponseWriter) WriteHeader(code int) {
	if grw.wroteHeader {
		return
	}
	grw.wroteHeader = true

	h := grw.ResponseWriter.Header()
	h.Del("Content-Length")
	h.Set("Content-Encoding", "gzip")
	h.Add("Vary", "Accept-Encoding")
	grw.ResponseWriter.WriteHeader(code)
}

func (grw *gzipResponseWriter) Flush() {
	grw.writer.Flush()
	if f, ok := grw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func Gzip(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		// WebSocket ve SSE'yi gzip'leme
		if r.Header.Get("Upgrade") != "" {
			next.ServeHTTP(w, r)
			return
		}

		gz := gzipWriterPool.Get().(*gzip.Writer)
		gz.Reset(w)
		defer func() {
			gz.Close()
			gzipWriterPool.Put(gz)
		}()

		grw := &gzipResponseWriter{
			ResponseWriter: w,
			writer:         gz,
		}
		next.ServeHTTP(grw, r)
	})
}
