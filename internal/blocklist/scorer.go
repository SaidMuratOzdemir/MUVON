package blocklist

import (
	"net"
	"sort"
	"sync"
	"time"
)

// Config holds the tunables the operator controls from the settings page.
type Config struct {
	Enabled    bool
	Threshold  int           // points that trigger a block
	Window     time.Duration // how long a hit keeps counting
	BaseTTL    time.Duration // first block duration
	MaxTTL     time.Duration // ceiling for the doubling ladder
	MaxEntries int           // memory bound on tracked clients
}

// DefaultConfig is deliberately conservative: blocking is off until the
// operator turns it on, because an appliance install may sit in front of an
// application that legitimately serves some of the scored filenames.
func DefaultConfig() Config {
	return Config{
		Enabled:    false,
		Threshold:  30,
		Window:     6 * time.Hour,
		BaseTTL:    15 * time.Minute,
		MaxTTL:     7 * 24 * time.Hour,
		MaxEntries: 100000,
	}
}

type hit struct {
	at    time.Time
	score int
}

type record struct {
	hits     []hit
	lastSeen time.Time
}

// banRecord remembers how many times a client has been blocked, independently
// of whether a block is currently in force.
type banRecord struct {
	count int
	last  time.Time
}

// banMemory is how long a ban count survives after the last block expires.
// Longer than MaxTTL so a repeat offender cannot reset the ladder by simply
// waiting out their longest ban.
const banMemory = 30 * 24 * time.Hour

// Block is one active decision. It is also the row shape the store persists and
// the panel renders, so the operator can always answer "why is this address
// blocked and what did it ask for".
type Block struct {
	Key       string    `json:"key"`     // IPv4 address or IPv6 /64 prefix
	Rule      string    `json:"rule"`    // which tier tripped it
	Pattern   string    `json:"pattern"` // the exact entry that matched
	Score     int       `json:"score"`
	BanCount  int       `json:"ban_count"`
	Permanent bool      `json:"permanent"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Decision is what the proxy acts on.
type Decision struct {
	Blocked     bool
	JustBlocked bool // first request that crossed the threshold, worth logging once
	Block       Block
	Score       int    // running total for this client
	Rule        string // rule of the pattern that matched this request, if any
	Pattern     string
}

// Scorer keeps the sliding-window scores and the active blocks. It lives in the
// proxy process, so every method has to stay cheap enough for the hot path: one
// mutex, map lookups, no allocation on the common "nothing matched" path.
type Scorer struct {
	mu     sync.Mutex
	hits   map[string]*record
	blocks map[string]*Block
	// bans outlives blocks on purpose. The doubling ladder is only meaningful
	// if the count survives the block it produced, so an offender who comes
	// back an hour after their first ban gets the longer second one rather
	// than starting over.
	bans  map[string]banRecord
	allow []*net.IPNet

	// patterns is swapped wholesale on config reload; the hot path only ever
	// reads it under the same lock it already takes.
	patterns *Set

	cfg Config

	// now is injectable so the window, the doubling ladder and the cleanup
	// loop can all be tested without sleeping.
	now func() time.Time

	// onBlock is called once, outside the lock, each time a client crosses the
	// threshold. The proxy uses it to persist the decision and share it with
	// the rest of the fleet. It must not block: it runs on the request path.
	onBlock func(Block)
}

// OnBlock registers the callback fired when a new block is decided. Replacing
// it mid-flight is allowed; passing nil disables it.
func (s *Scorer) OnBlock(fn func(Block)) {
	s.mu.Lock()
	s.onBlock = fn
	s.mu.Unlock()
}

// New builds a Scorer. allowCIDRs entries that fail to parse are skipped rather
// than rejected: a typo in one allowlist row must not disable the whole thing.
func New(cfg Config, allowCIDRs []string, patterns *Set) *Scorer {
	s := &Scorer{
		hits:     make(map[string]*record),
		blocks:   make(map[string]*Block),
		bans:     make(map[string]banRecord),
		patterns: patterns,
		cfg:      cfg,
		now:      time.Now,
	}
	s.SetAllowlist(allowCIDRs)
	return s
}

// SetPatterns swaps the compiled pattern table. Called on config reload.
func (s *Scorer) SetPatterns(set *Set) {
	s.mu.Lock()
	s.patterns = set
	s.mu.Unlock()
}

// SetConfig swaps the tunables in place. Called on config reload.
func (s *Scorer) SetConfig(cfg Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
}

// SetAllowlist replaces the never-block list. A bare address is accepted and
// treated as a single-host network.
func (s *Scorer) SetAllowlist(entries []string) {
	nets := make([]*net.IPNet, 0, len(entries))
	for _, e := range entries {
		if e == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			nets = append(nets, n)
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	s.mu.Lock()
	s.allow = nets
	s.mu.Unlock()
}

// Observe scores one request and reports whether the client should be refused.
//
// It is the only call the proxy makes: scoring and the block check share a lock
// acquisition, so an already-blocked client costs one map lookup.
func (s *Scorer) Observe(clientIP, path string) Decision {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.cfg.Enabled {
		return Decision{}
	}

	key := Key(clientIP)
	if key == "" || s.isAllowedLocked(clientIP) {
		return Decision{}
	}

	now := s.now()

	// Already blocked? Answer before doing any pattern work.
	if b, ok := s.blocks[key]; ok {
		if b.Permanent || b.ExpiresAt.After(now) {
			return Decision{Blocked: true, Block: *b}
		}
		// Expired. Keep the ban count: it is what makes the next block longer.
		delete(s.blocks, key)
	}

	m := s.patterns.Score(path)
	if m.Score == 0 {
		return Decision{}
	}

	rec := s.hits[key]
	if rec == nil {
		rec = &record{}
		s.hits[key] = rec
		s.evictIfNeededLocked()
	}
	rec.lastSeen = now
	rec.hits = pruneHits(rec.hits, now, s.cfg.Window)
	rec.hits = append(rec.hits, hit{at: now, score: m.Score})

	total := 0
	for _, h := range rec.hits {
		total += h.score
	}

	d := Decision{Score: total, Rule: m.Rule, Pattern: m.Pattern}
	if total < s.cfg.Threshold {
		return d
	}

	b := s.blockLocked(key, m, total, now)
	d.Blocked = true
	d.JustBlocked = true
	d.Block = b

	// Fire outside the lock: the callback persists to the database, and holding
	// the scorer's mutex across a network round trip would stall every other
	// request on this proxy.
	if fn := s.onBlock; fn != nil {
		go fn(b)
	}
	return d
}

// blockLocked records a block and applies the doubling ladder. Caller holds mu.
func (s *Scorer) blockLocked(key string, m Match, total int, now time.Time) Block {
	banCount := s.bans[key].count + 1
	s.bans[key] = banRecord{count: banCount, last: now}

	ttl := s.cfg.BaseTTL
	// Double per repeat offence, capped. Shift is bounded so a long-lived
	// offender cannot overflow the duration.
	if shift := banCount - 1; shift > 0 {
		if shift > 20 {
			shift = 20
		}
		ttl = s.cfg.BaseTTL << uint(shift)
	}
	if ttl > s.cfg.MaxTTL || ttl <= 0 {
		ttl = s.cfg.MaxTTL
	}

	b := &Block{
		Key:       key,
		Rule:      m.Rule,
		Pattern:   m.Pattern,
		Score:     total,
		BanCount:  banCount,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	s.blocks[key] = b
	// The score has done its job; start the next window clean so a returning
	// offender is judged on fresh behaviour rather than a stale total.
	delete(s.hits, key)
	return *b
}

// Blocked reports whether a client is currently refused, without scoring.
func (s *Scorer) Blocked(clientIP string) (Block, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.blocks[Key(clientIP)]
	if !ok {
		return Block{}, false
	}
	if !b.Permanent && !b.ExpiresAt.After(s.now()) {
		return Block{}, false
	}
	return *b, true
}

// Apply installs a block decided elsewhere: loaded from the store at startup or
// pushed by central over the command channel. Idempotent, because command
// delivery is at-least-once.
func (s *Scorer) Apply(b Block) {
	if b.Key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocks[b.Key] = &b
	delete(s.hits, b.Key)
}

// Remove lifts a block. Returns false when there was nothing to lift.
func (s *Scorer) Remove(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.blocks[key]
	delete(s.blocks, key)
	delete(s.hits, key)
	// Lifting a block is an operator saying "this one was wrong", so the
	// penalty ladder resets too. Otherwise the next honest mistake would be
	// punished twice as long.
	delete(s.bans, key)
	return ok
}

// Flush drops every block and every score. This is the panic button; the
// operator reaches for it when a block is cutting real traffic.
func (s *Scorer) Flush() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.blocks)
	s.blocks = make(map[string]*Block)
	s.hits = make(map[string]*record)
	s.bans = make(map[string]banRecord)
	return n
}

// List returns the active blocks, newest first, for the panel and the store.
func (s *Scorer) List() []Block {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	out := make([]Block, 0, len(s.blocks))
	for _, b := range s.blocks {
		if b.Permanent || b.ExpiresAt.After(now) {
			out = append(out, *b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Sweep drops expired blocks and idle score records. Runs on a ticker; also
// called directly by tests.
func (s *Scorer) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, b := range s.blocks {
		if !b.Permanent && !b.ExpiresAt.After(now) {
			delete(s.blocks, k)
		}
	}
	cutoff := now.Add(-s.cfg.Window)
	for k, r := range s.hits {
		if r.lastSeen.Before(cutoff) {
			delete(s.hits, k)
		}
	}
	banCutoff := now.Add(-banMemory)
	for k, b := range s.bans {
		if b.last.Before(banCutoff) {
			delete(s.bans, k)
		}
	}
}

// Run starts the sweep loop and returns when ctx's channel closes.
func (s *Scorer) Run(done <-chan struct{}, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			s.Sweep()
		}
	}
}

// evictIfNeededLocked bounds memory. Caller holds mu.
//
// Under a distributed scan the tracked-client count is attacker-controlled, so
// this is a real limit and not a formality: without it a rotating source could
// grow the map until the process dies. Oldest-seen records go first; they are
// the least likely to be mid-attack.
func (s *Scorer) evictIfNeededLocked() {
	if s.cfg.MaxEntries <= 0 || len(s.hits) <= s.cfg.MaxEntries {
		return
	}
	type kv struct {
		key  string
		seen time.Time
	}
	all := make([]kv, 0, len(s.hits))
	for k, r := range s.hits {
		all = append(all, kv{k, r.lastSeen})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].seen.Before(all[j].seen) })
	drop := len(s.hits) - s.cfg.MaxEntries
	for i := 0; i < drop && i < len(all); i++ {
		delete(s.hits, all[i].key)
	}
}

func (s *Scorer) isAllowedLocked(clientIP string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	for _, n := range s.allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Key normalises a client address into the unit that gets scored and blocked.
//
// IPv4 is scored per address. IPv6 is scored per /64, because that is the
// smallest block an ISP hands a single subscriber: scoring full IPv6 addresses
// would let one client rotate through billions of them and never accumulate a
// score. Returns "" for input that is not an address, which the caller treats
// as "do not track".
func Key(clientIP string) string {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	masked := ip.Mask(net.CIDRMask(64, 128))
	return masked.String() + "/64"
}

// pruneHits drops entries that fell out of the window. Same shape as the
// correlation engine's appendPrune, kept separate because this one carries a
// weight alongside the timestamp.
func pruneHits(hits []hit, now time.Time, window time.Duration) []hit {
	cutoff := now.Add(-window)
	start := 0
	for start < len(hits) && hits[start].at.Before(cutoff) {
		start++
	}
	if start > 0 {
		return hits[start:]
	}
	return hits
}
