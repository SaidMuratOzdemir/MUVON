package logger

import (
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// GeoEnricher resolves a client IP to country and city.
type GeoEnricher func(ip string) (country, city string)

// IdentityEnricher extracts JWT identity from a raw bearer-style header.
// The host is passed alongside the header value so the caller can pick a
// host-scoped JWT config (per-customer secret, different claim shapes)
// before falling back to a global setting. The pipeline picks which
// request header to read via IdentityHeaderResolver below.
type IdentityEnricher func(host, headerValue string) *UserIdentity

// IdentityHeaderResolver returns the request header name that the SIEM
// should inspect for a bearer-style token on a given host. Empty / unknown
// host → "Authorization". This indirection exists because some tenants
// authenticate with X-Auth-Token / X-Access-Token; previously the pipeline
// hard-coded "Authorization" and silently skipped enrichment for those
// hosts.
type IdentityHeaderResolver func(host string) string

// RawTokenPolicy returns whether a host opted into persisting the raw
// bearer token alongside the log entry. Default behaviour (no resolver
// or false) is to drop the token after enrichment.
type RawTokenPolicy func(host string) bool

type Pipeline struct {
	ch         chan Entry
	pool       *pgxpool.Pool
	workerWg   sync.WaitGroup
	quit       chan struct{}
	closed     atomic.Bool
	dropped    atomic.Int64
	enqueued   atomic.Int64
	subMu      sync.RWMutex
	subs       map[chan Entry]struct{}

	enrichMu       sync.RWMutex
	geoFn          GeoEnricher
	jwtFn          IdentityEnricher
	jwtHeaderFn    IdentityHeaderResolver
	rawTokenFn     RawTokenPolicy
}

// SetGeoEnricher sets the function used to resolve IPs to country/city.
// Safe to call after pipeline creation (e.g. after GeoIP DB loads).
func (p *Pipeline) SetGeoEnricher(fn GeoEnricher) {
	p.enrichMu.Lock()
	p.geoFn = fn
	p.enrichMu.Unlock()
}

// SetIdentityEnricher sets the function used to extract JWT identity from
// the configured identity header.
func (p *Pipeline) SetIdentityEnricher(fn IdentityEnricher) {
	p.enrichMu.Lock()
	p.jwtFn = fn
	p.enrichMu.Unlock()
}

// SetIdentityHeaderResolver sets the function used to pick which request
// header carries the bearer token for a given host. Empty resolver or
// empty return value defaults to "Authorization".
func (p *Pipeline) SetIdentityHeaderResolver(fn IdentityHeaderResolver) {
	p.enrichMu.Lock()
	p.jwtHeaderFn = fn
	p.enrichMu.Unlock()
}

// SetRawTokenPolicy registers the per-host opt-in for raw token capture.
func (p *Pipeline) SetRawTokenPolicy(fn RawTokenPolicy) {
	p.enrichMu.Lock()
	p.rawTokenFn = fn
	p.enrichMu.Unlock()
}

func NewPipeline(pool *pgxpool.Pool, bufferSize, workerCount, batchSize int, flushInterval time.Duration) *Pipeline {
	p := &Pipeline{
		ch:   make(chan Entry, bufferSize),
		pool: pool,
		quit: make(chan struct{}),
		subs: make(map[chan Entry]struct{}),
	}

	for i := 0; i < workerCount; i++ {
		w := newWorker(i, pool, p.ch, batchSize, flushInterval, p.quit)
		p.workerWg.Add(1)
		go func() {
			defer p.workerWg.Done()
			w.run()
		}()
	}

	slog.Info("log pipeline started", "buffer", bufferSize, "workers", workerCount, "batch", batchSize)
	return p
}

func (p *Pipeline) Send(entry Entry) {
	if p.closed.Load() {
		return
	}

	// Enrich with GeoIP and JWT identity — happens centrally here so
	// both hub-local and agent-forwarded logs are treated identically.
	p.enrichMu.RLock()
	geoFn := p.geoFn
	jwtFn := p.jwtFn
	headerFn := p.jwtHeaderFn
	rawFn := p.rawTokenFn
	p.enrichMu.RUnlock()

	if geoFn != nil && entry.Country == "" {
		entry.Country, entry.City = geoFn(entry.ClientIP)
	}
	if jwtFn != nil && entry.UserIdentity == nil {
		header := "Authorization"
		if headerFn != nil {
			if h := headerFn(entry.Host); h != "" {
				header = h
			}
		}
		if val := identityHeaderValue(entry.RequestHeaders, header); val != "" {
			entry.UserIdentity = jwtFn(entry.Host, val)
			// Stamp the raw token only when the host has explicitly opted
			// in. Strip the "Bearer " prefix so the column always holds a
			// pure JWT — saves the UI from re-parsing on every reveal.
			if rawFn != nil && entry.RawJWT == "" && rawFn(entry.Host) {
				entry.RawJWT = stripBearerPrefix(val)
			}
		}
	}

	// Sanitize sensitive headers before they enter the channel / get written to DB.
	entry.RequestHeaders = SanitizeHeaders(entry.RequestHeaders)
	entry.ResponseHeaders = SanitizeHeaders(entry.ResponseHeaders)

	select {
	case p.ch <- entry:
		p.enqueued.Add(1)
	default:
		p.dropped.Add(1)
		slog.Warn("log pipeline full, dropping entry", "dropped_total", p.dropped.Load())
	}

	// Fan-out to SSE subscribers — non-blocking, drop if subscriber is slow
	p.subMu.RLock()
	for sub := range p.subs {
		select {
		case sub <- entry:
		default:
		}
	}
	p.subMu.RUnlock()
}

// Subscribe returns a channel that receives every log entry as it is sent.
// The caller must call Unsubscribe when done to avoid leaks.
func (p *Pipeline) Subscribe() chan Entry {
	ch := make(chan Entry, 100)
	p.subMu.Lock()
	p.subs[ch] = struct{}{}
	p.subMu.Unlock()
	return ch
}

// Unsubscribe removes the subscriber channel and closes it.
func (p *Pipeline) Unsubscribe(ch chan Entry) {
	p.subMu.Lock()
	delete(p.subs, ch)
	p.subMu.Unlock()
	close(ch)
}

func (p *Pipeline) Stop() {
	if !p.closed.CompareAndSwap(false, true) {
		return
	}
	slog.Info("log pipeline shutting down", "queued", len(p.ch))
	close(p.quit)
	close(p.ch)
	p.workerWg.Wait()
	slog.Info("log pipeline stopped", "total_enqueued", p.enqueued.Load(), "total_dropped", p.dropped.Load())
}

func (p *Pipeline) Stats() (enqueued, dropped int64, queueLen int) {
	return p.enqueued.Load(), p.dropped.Load(), len(p.ch)
}

// identityHeaderValue resolves the bearer-style identity header. It
// supports two encodings:
//
//   - "Header-Name" (default for "Authorization", X-Auth-Token, X-Access-Token):
//     returns the header value verbatim. The downstream extractor strips the
//     "Bearer " prefix when present.
//   - "Cookie:<name>": returns the value of the named cookie from the
//     Cookie header. This lets a host whose JS app keeps the JWT in a
//     cookie (rather than the Authorization header) still get enriched.
//     We do not parse Set-Cookie because it never appears on requests.
//
// Header lookup is case-insensitive — some upstream proxies normalise to
// lower-case and we do not want that cosmetic difference to silently
// disable identity enrichment.
func identityHeaderValue(headers map[string]string, spec string) string {
	if spec == "" {
		spec = "Authorization"
	}
	if !strings.HasPrefix(strings.ToLower(spec), "cookie:") {
		v := headerCaseInsensitive(headers, spec)
		if v == "" {
			return ""
		}
		// If the host put a raw token (no "Bearer ") in a non-standard
		// header, make it look like a Bearer to the downstream extractor.
		// Only do this for non-Authorization headers — Authorization is
		// expected to follow RFC 6750 and already include the scheme.
		if !strings.EqualFold(spec, "Authorization") &&
			!strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "bearer ") {
			return "Bearer " + v
		}
		return v
	}
	// Cookie:<name> — pull <name> out of the Cookie header.
	cookieName := strings.TrimSpace(spec[len("cookie:"):])
	if cookieName == "" {
		return ""
	}
	rawCookie := headerCaseInsensitive(headers, "Cookie")
	if rawCookie == "" {
		return ""
	}
	for _, part := range strings.Split(rawCookie, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		if strings.EqualFold(kv[0], cookieName) {
			val := strings.TrimSpace(kv[1])
			if val == "" {
				return ""
			}
			// Cookie values rarely include "Bearer " — wrap so the
			// extractor's prefix check accepts the token.
			if !strings.HasPrefix(strings.ToLower(val), "bearer ") {
				return "Bearer " + val
			}
			return val
		}
	}
	return ""
}

// stripBearerPrefix returns the bearer token without the leading scheme.
// Tolerates extra whitespace and any casing of "Bearer".
func stripBearerPrefix(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 7 && strings.EqualFold(s[:7], "Bearer ") {
		return strings.TrimSpace(s[7:])
	}
	return s
}

// headerCaseInsensitive finds a header by lowercase comparison. Some
// upstream proxies send "authorization" lowercase; we do not want that
// cosmetic difference to silently disable identity enrichment.
func headerCaseInsensitive(h map[string]string, key string) string {
	if v, ok := h[key]; ok && v != "" {
		return v
	}
	lk := ""
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		lk += string(c)
	}
	for k, v := range h {
		lower := ""
		for i := 0; i < len(k); i++ {
			c := k[i]
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			lower += string(c)
		}
		if lower == lk {
			return v
		}
	}
	return ""
}
