package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSRFMiddlewareAllowsSafeMethods(t *testing.T) {
	handler := csrfMiddleware(nil)(next200())
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		req := httptest.NewRequest(method, "/api/hosts", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: got %d, want 200", method, rr.Code)
		}
	}
}

func TestCSRFMiddlewareAllowsBypassedPaths(t *testing.T) {
	handler := csrfMiddleware(map[string]bool{"/api/auth/login": true})(next200())
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("bypassed path should pass: got %d", rr.Code)
	}
}

func TestCSRFMiddlewareRejectsMissingCookie(t *testing.T) {
	handler := csrfMiddleware(nil)(next200())
	req := httptest.NewRequest(http.MethodPost, "/api/hosts", nil)
	req.Header.Set(csrfHeader, "something")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("missing cookie should be 403, got %d", rr.Code)
	}
}

func TestCSRFMiddlewareRejectsMissingHeader(t *testing.T) {
	handler := csrfMiddleware(nil)(next200())
	req := httptest.NewRequest(http.MethodPost, "/api/hosts", nil)
	req.AddCookie(&http.Cookie{Name: cookieCSRF, Value: "abc"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("missing header should be 403, got %d", rr.Code)
	}
}

func TestCSRFMiddlewareRejectsMismatch(t *testing.T) {
	handler := csrfMiddleware(nil)(next200())
	req := httptest.NewRequest(http.MethodPost, "/api/hosts", nil)
	req.AddCookie(&http.Cookie{Name: cookieCSRF, Value: "abc"})
	req.Header.Set(csrfHeader, "xyz")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("mismatch should be 403, got %d", rr.Code)
	}
}

func TestCSRFMiddlewareAcceptsMatchingPair(t *testing.T) {
	handler := csrfMiddleware(nil)(next200())
	req := httptest.NewRequest(http.MethodPost, "/api/hosts", nil)
	req.AddCookie(&http.Cookie{Name: cookieCSRF, Value: "deadbeef"})
	req.Header.Set(csrfHeader, "deadbeef")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("matching pair should pass: got %d", rr.Code)
	}
}

func next200() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}
