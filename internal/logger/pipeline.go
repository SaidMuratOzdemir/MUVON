package logger

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// GeoEnricher resolves a client IP to country and city.
type GeoEnricher func(ip string) (country, city string)

// IdentityEnricher extracts JWT identity from a raw Authorization header.
// The host is passed alongside the header so the caller can pick a
// host-scoped JWT config (per-customer secret, different claim shapes)
// before falling back to a global setting.
type IdentityEnricher func(host, authHeader string) *UserIdentity

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

	enrichMu sync.RWMutex
	geoFn    GeoEnricher
	jwtFn    IdentityEnricher
}

// SetGeoEnricher sets the function used to resolve IPs to country/city.
// Safe to call after pipeline creation (e.g. after GeoIP DB loads).
func (p *Pipeline) SetGeoEnricher(fn GeoEnricher) {
	p.enrichMu.Lock()
	p.geoFn = fn
	p.enrichMu.Unlock()
}

// SetIdentityEnricher sets the function used to extract JWT identity from Authorization headers.
func (p *Pipeline) SetIdentityEnricher(fn IdentityEnricher) {
	p.enrichMu.Lock()
	p.jwtFn = fn
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
	p.enrichMu.RUnlock()

	if geoFn != nil && entry.Country == "" {
		entry.Country, entry.City = geoFn(entry.ClientIP)
	}
	if jwtFn != nil && entry.UserIdentity == nil {
		if auth := headerCaseInsensitive(entry.RequestHeaders, "Authorization"); auth != "" {
			entry.UserIdentity = jwtFn(entry.Host, auth)
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
