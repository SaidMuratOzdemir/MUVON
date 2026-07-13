package proxy

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// accelInterceptWriter wraps ResponseWriter and intercepts X-Accel-Redirect.
// When the backend sets this header, the proxy swallows the backend body and
// instead serves the local file directly via http.ServeContent.
type accelInterceptWriter struct {
	http.ResponseWriter
	r           *http.Request
	accelRoot   string
	intercepted bool
}

func (w *accelInterceptWriter) WriteHeader(code int) {
	accelPath := w.Header().Get("X-Accel-Redirect")
	if accelPath == "" {
		w.ResponseWriter.WriteHeader(code)
		return
	}

	// Intercept — serve the local file instead.
	w.intercepted = true
	w.Header().Del("X-Accel-Redirect")
	serveAccelFile(w.ResponseWriter, w.r, w.accelRoot, accelPath)
}

func (w *accelInterceptWriter) Write(b []byte) (int, error) {
	if w.intercepted {
		// Discard backend body; file was already served.
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

func (w *accelInterceptWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack delegates to the underlying writer so wrapping an accel route that
// happens to carry a genuine connection upgrade still works.
func (w *accelInterceptWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// newAccelWriter wraps w only when the route has an accel_root configured.
func newAccelWriter(w http.ResponseWriter, r *http.Request, accelRoot string) *accelInterceptWriter {
	return &accelInterceptWriter{
		ResponseWriter: w,
		r:              r,
		accelRoot:      accelRoot,
	}
}

// serveSignedAccel validates the signed URL token and serves the local file directly,
// bypassing the backend entirely.
//
// URL format: /path/to/file?token=<hex-hmac>&expires=<unix-timestamp>
// Token = HMAC-SHA256(secret, path+":"+expires), hex-encoded.
func serveSignedAccel(w http.ResponseWriter, r *http.Request, accelRoot, secret string) {
	q := r.URL.Query()
	tokenHex := q.Get("token")
	expiresStr := q.Get("expires")

	if tokenHex == "" || expiresStr == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	expires, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil || time.Now().Unix() > expires {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Verify HMAC-SHA256(secret, path+":"+expires).
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(r.URL.Path + ":" + expiresStr))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(tokenHex), []byte(expected)) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	serveAccelFile(w, r, accelRoot, r.URL.Path)
}

// serveAccelFile resolves the path inside accelRoot and serves it via http.ServeContent.
func serveAccelFile(w http.ResponseWriter, r *http.Request, accelRoot, accelPath string) {
	clean := path.Clean("/" + accelPath)
	fullPath := filepath.Join(accelRoot, filepath.FromSlash(clean))

	// Ensure the resolved path stays inside accelRoot.
	root := filepath.Clean(accelRoot)
	if !strings.HasPrefix(fullPath, root+string(os.PathSeparator)) && fullPath != root {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	f, err := os.Open(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		http.NotFound(w, r)
		return
	}

	if w.Header().Get("Content-Type") == "" {
		if ct := mime.TypeByExtension(filepath.Ext(fullPath)); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
	}

	// Accel-served files are protected (auth-gated) media. Default to private so
	// a shared CDN (Cloudflare) or browser never caches one user's document where
	// another could receive it. Backend may override via its own Cache-Control.
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "private, no-store")
	}

	http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
}
