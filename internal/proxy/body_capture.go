package proxy

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
)

type CapturedBody struct {
	Data      []byte
	Size      int
	Truncated bool
}

func CaptureRequestBody(r *http.Request, maxSize int) (*http.Request, *CapturedBody, error) {
	if r.Body == nil || r.ContentLength == 0 {
		return r, &CapturedBody{}, nil
	}

	if shouldSkipCapture(r.Header.Get("Content-Type")) {
		return r, &CapturedBody{Size: int(r.ContentLength)}, nil
	}

	// Gövdeyi tümüyle oku: forward edilen kopya asla kısaltılmaz, yalnız
	// SIEM kopyası maxSize'da kırpılır (Truncated bayrağı ile). Okuma hatası
	// (client bağlantısı koptu ya da MaxBytesReader limiti aşıldı) durumunda
	// kısmi gövdeyi "tam" gibi backend'e ASLA iletme — hatayı yukarı taşı,
	// çağıran isteği reddetsin.
	full, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return r, nil, err
	}

	captured := full
	truncated := false
	if len(captured) > maxSize {
		captured = captured[:maxSize]
		truncated = true
	}

	r.Body = io.NopCloser(bytes.NewReader(full))
	r.ContentLength = int64(len(full))

	return r, &CapturedBody{
		Data:      captured,
		Size:      len(full),
		Truncated: truncated,
	}, nil
}

type ResponseCapture struct {
	http.ResponseWriter
	statusCode  int
	buf         bytes.Buffer
	maxSize     int
	truncated   bool
	wroteHeader bool
	totalSize   int
	headers     http.Header
}

func NewResponseCapture(w http.ResponseWriter, maxSize int, skipCapture bool) *ResponseCapture {
	rc := &ResponseCapture{
		ResponseWriter: w,
		statusCode:     200,
		maxSize:        maxSize,
		headers:        make(http.Header),
	}
	if skipCapture {
		rc.maxSize = 0
	}
	return rc
}

func (rc *ResponseCapture) WriteHeader(code int) {
	if rc.wroteHeader {
		return
	}
	rc.wroteHeader = true
	rc.statusCode = code

	// Response header'larını kaydet
	for k, v := range rc.ResponseWriter.Header() {
		rc.headers[k] = v
	}

	rc.ResponseWriter.WriteHeader(code)
}

func (rc *ResponseCapture) Write(b []byte) (int, error) {
	if !rc.wroteHeader {
		rc.WriteHeader(200)
	}
	rc.totalSize += len(b)

	if rc.maxSize > 0 {
		room := rc.maxSize - rc.buf.Len()
		if room >= len(b) {
			rc.buf.Write(b)
		} else {
			if room > 0 {
				rc.buf.Write(b[:room])
			}
			rc.truncated = true
		}
	}

	return rc.ResponseWriter.Write(b)
}

func (rc *ResponseCapture) Flush() {
	if f, ok := rc.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rc *ResponseCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := rc.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (rc *ResponseCapture) StatusCode() int {
	return rc.statusCode
}

func (rc *ResponseCapture) CapturedBody() *CapturedBody {
	return &CapturedBody{
		Data:      rc.buf.Bytes(),
		Size:      rc.totalSize,
		Truncated: rc.truncated,
	}
}

func (rc *ResponseCapture) CapturedHeaders() map[string]string {
	out := make(map[string]string, len(rc.headers))
	for k, v := range rc.headers {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

func shouldSkipCapture(contentType string) bool {
	ct := strings.ToLower(contentType)
	skipTypes := []string{
		"multipart/form-data",
		"application/octet-stream",
		"image/",
		"video/",
		"audio/",
		"application/zip",
		"application/gzip",
		"application/pdf",
	}
	for _, skip := range skipTypes {
		if strings.Contains(ct, skip) {
			return true
		}
	}
	return false
}
