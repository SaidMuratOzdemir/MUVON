package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
)

func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				stack := debug.Stack()
				slog.Error("panic recovered",
					"error", fmt.Sprint(err),
					"path", r.URL.Path,
					"method", r.Method,
					"stack", string(stack),
				)
				if !headersSent(w) {
					w.WriteHeader(http.StatusInternalServerError)
				}
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func headersSent(w http.ResponseWriter) bool {
	// A heuristic: a Content-Type on the header means something was written.
	return w.Header().Get("Content-Type") != ""
}
