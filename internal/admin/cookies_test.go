package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSetAccessCookieFlags(t *testing.T) {
	rr := httptest.NewRecorder()
	setAccessCookie(rr, "jwt.value.here", time.Now().Add(15*time.Minute))
	c := findCookie(t, rr.Result().Cookies(), cookieAccess)
	if !c.HttpOnly {
		t.Error("access cookie must be HttpOnly")
	}
	if !c.Secure {
		t.Error("access cookie must be Secure")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Error("access cookie must be SameSite=Strict")
	}
	if c.Path != "/" {
		t.Errorf("access cookie Path = %q, want /", c.Path)
	}
}

func TestSetRefreshCookieIsScopedToAuthPath(t *testing.T) {
	rr := httptest.NewRecorder()
	setRefreshCookie(rr, "opaque-refresh", time.Now().Add(30*24*time.Hour))
	c := findCookie(t, rr.Result().Cookies(), cookieRefresh)
	if c.Path != refreshCookiePath {
		t.Errorf("refresh cookie Path = %q, want %q", c.Path, refreshCookiePath)
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("refresh cookie missing hardening flags: %+v", c)
	}
}

func TestSetCSRFCookieIsReadableByJS(t *testing.T) {
	rr := httptest.NewRecorder()
	setCSRFCookie(rr, "csrf-token", time.Now().Add(30*24*time.Hour))
	c := findCookie(t, rr.Result().Cookies(), cookieCSRF)
	if c.HttpOnly {
		t.Error("csrf cookie must NOT be HttpOnly (SPA reads it)")
	}
	if !c.Secure {
		t.Error("csrf cookie must be Secure")
	}
}

func TestClearAuthCookiesExpiresAll(t *testing.T) {
	rr := httptest.NewRecorder()
	clearAuthCookies(rr)
	cookies := rr.Result().Cookies()
	names := map[string]bool{}
	for _, c := range cookies {
		names[c.Name] = true
		if c.MaxAge != -1 {
			t.Errorf("cookie %q should be cleared with MaxAge=-1, got %d", c.Name, c.MaxAge)
		}
	}
	for _, want := range []string{cookieAccess, cookieRefresh, cookieCSRF} {
		if !names[want] {
			t.Errorf("clearAuthCookies did not clear %q", want)
		}
	}
}

func findCookie(t *testing.T, cs []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, c := range cs {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("cookie %q not set", name)
	return nil
}
