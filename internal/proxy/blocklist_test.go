package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"muvon/internal/blocklist"
	"muvon/internal/config"
	"muvon/internal/db"
	"muvon/internal/logger"
)

// blockTestHandler wires a Handler with one host, one catch-all static route
// and a scorer, which is the smallest shape that exercises the real request
// path rather than the scorer in isolation.
func blockTestHandler(t *testing.T, enabled bool) (*Handler, *blocklist.Scorer) {
	t.Helper()

	set, errs := blocklist.Compile(blocklist.DefaultPatterns())
	if len(errs) > 0 {
		t.Fatalf("default patterns did not compile: %v", errs)
	}
	cfg := blocklist.DefaultConfig()
	cfg.Enabled = enabled
	scorer := blocklist.New(cfg, nil, set)

	backend := "http://127.0.0.1:1"
	holder := config.NewHolder(nil, nil)
	if err := holder.Seed(&config.Config{
		Hosts: map[string]*config.HostConfig{
			"shop.example.com": {
				Host: db.Host{ID: 1, Domain: "shop.example.com", IsActive: true},
				Routes: []config.RouteRule{{
					Route:      db.Route{ID: 1, PathPrefix: "/", RouteType: "proxy", BackendURL: &backend},
					PathPrefix: "/",
				}},
			},
		},
	}); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	h := NewHandler(holder, nil, http.DefaultTransport, nil, nil, "", "")
	h.SetBlocker(scorer)
	return h, scorer
}

func doRequest(h *Handler, remoteAddr, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "shop.example.com"
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The whole point of putting the check in the proxy: a credential probe is
// refused by the edge itself, without the request ever reaching a route.
func TestProxyRefusesBlockedClient(t *testing.T) {
	h, scorer := blockTestHandler(t, true)

	// First request scores 100 and trips the block, so it is already refused.
	if rec := doRequest(h, "203.0.113.7:5555", "/.env"); rec.Code != http.StatusForbidden {
		t.Fatalf("first probe: status %d, want 403", rec.Code)
	}
	if _, ok := scorer.Blocked("203.0.113.7"); !ok {
		t.Fatal("client should be blocked after a credential probe")
	}

	// Every later request from that address is refused too, whatever it asks
	// for. This is what stops the 244-request burst seen in production.
	if rec := doRequest(h, "203.0.113.7:5555", "/"); rec.Code != http.StatusForbidden {
		t.Fatalf("follow-up request: status %d, want 403", rec.Code)
	}
}

// A client that never matches a pattern must be untouched by the feature.
func TestProxyLeavesOrdinaryTrafficAlone(t *testing.T) {
	h, scorer := blockTestHandler(t, true)

	// Reaches the route and fails at the backend dial, which is the point:
	// it got past blocking.
	rec := doRequest(h, "203.0.113.8:5555", "/api/orders")
	if rec.Code == http.StatusForbidden {
		t.Fatal("ordinary request was blocked")
	}
	if _, ok := scorer.Blocked("203.0.113.8"); ok {
		t.Fatal("ordinary client must not be blocked")
	}
}

// With the feature off the scorer must be completely inert, because that is the
// state every existing installation upgrades into.
func TestProxyDisabledBlockingIsInert(t *testing.T) {
	h, scorer := blockTestHandler(t, false)

	for i := 0; i < 5; i++ {
		if rec := doRequest(h, "203.0.113.9:5555", "/.env"); rec.Code == http.StatusForbidden {
			t.Fatal("blocking is disabled but a request was refused")
		}
	}
	if _, ok := scorer.Blocked("203.0.113.9"); ok {
		t.Fatal("disabled scorer must not record blocks")
	}
}

// A block applied from central (or restored at startup) is enforced locally
// even though this proxy never saw the offending request itself.
func TestProxyEnforcesCentrallyAppliedBlock(t *testing.T) {
	h, scorer := blockTestHandler(t, true)

	scorer.Apply(blocklist.Block{
		Key:       "203.0.113.10",
		Rule:      blocklist.RuleSecret,
		Pattern:   ".env",
		Score:     100,
		BanCount:  1,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})

	if rec := doRequest(h, "203.0.113.10:5555", "/"); rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403 for a fleet-applied block", rec.Code)
	}
}

// recordingSink captures shipped log entries so a test can assert on the row
// the operator will read, not only on the status code the client saw.
type recordingSink struct {
	mu      sync.Mutex
	entries []logger.Entry
}

func (s *recordingSink) Send(e logger.Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, e)
}

func (s *recordingSink) SendClientEvents(logger.ClientEventBatch) {}

func (s *recordingSink) snapshot() []logger.Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]logger.Entry(nil), s.entries...)
}

// A refusal is the event the operator opens the log to find, so it has to be
// written even though the request never reached a route.
func TestProxyLogsRefusedRequest(t *testing.T) {
	h, _ := blockTestHandler(t, true)
	sink := &recordingSink{}
	h.logSink = sink

	if rec := doRequest(h, "203.0.113.7:5555", "/.env"); rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}

	got := sink.snapshot()
	if len(got) != 1 {
		t.Fatalf("shipped %d entries, want 1", len(got))
	}
	e := got[0]
	if e.ResponseStatus != http.StatusForbidden {
		t.Errorf("logged status %d, want 403", e.ResponseStatus)
	}
	if e.Path != "/.env" {
		t.Errorf("logged path %q, want /.env", e.Path)
	}
	if e.ClientIP != "203.0.113.7" {
		t.Errorf("logged client %q, want 203.0.113.7", e.ClientIP)
	}
	if e.Host != "shop.example.com" {
		t.Errorf("logged host %q, want shop.example.com", e.Host)
	}
}

// Enforcement must not depend on the log budget: once it is spent the client
// is still refused, it just stops producing rows.
func TestProxyKeepsRefusingAfterLogBudget(t *testing.T) {
	h, _ := blockTestHandler(t, true)
	sink := &recordingSink{}
	h.logSink = sink

	const requests = 300
	for i := 0; i < requests; i++ {
		if rec := doRequest(h, "203.0.113.7:5555", "/.env"); rec.Code != http.StatusForbidden {
			t.Fatalf("request %d: status %d, want 403", i, rec.Code)
		}
	}

	n := len(sink.snapshot())
	if n == 0 {
		t.Fatal("no refusal was logged at all")
	}
	if n >= requests {
		t.Errorf("logged %d of %d refusals, want a bounded subset", n, requests)
	}
}
