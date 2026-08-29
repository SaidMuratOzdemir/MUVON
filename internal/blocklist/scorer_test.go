package blocklist

import (
	"testing"
	"time"
)

// testPatterns compiles the shipped default set, which is what a fresh install
// runs with.
func testPatterns(t *testing.T) *Set {
	t.Helper()
	set, errs := Compile(DefaultPatterns())
	if len(errs) > 0 {
		t.Fatalf("default patterns failed to compile: %v", errs)
	}
	return set
}

// newTestScorer builds a scorer with blocking on and a controllable clock.
func newTestScorer(t *testing.T) (*Scorer, *time.Time) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Enabled = true
	s := New(cfg, nil, testPatterns(t))
	clock := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return clock }
	return s, &clock
}

// The seven scanners below are not invented: every address and path was
// observed in production traffic over a 24 hour window. The table is the
// design's acceptance test. If a change lets a real scanner survive longer
// than it does here, that change is a regression.
func TestObservedScannersAreBlocked(t *testing.T) {
	cases := []struct {
		name        string
		ip          string
		paths       []string
		wantBlockAt int // 1-indexed request that should trip the block, 0 = never
	}{
		{
			name:        "credential hunt over AWS",
			ip:          "44.192.5.227",
			paths:       []string{"/.env.backup1", "/.git/.env", "/.config/gcloud/application_default_credentials.json"},
			wantBlockAt: 1,
		},
		{
			name:        "env sweep from Google Cloud",
			ip:          "34.10.168.102",
			paths:       []string{"/.env", "/.env.prod", "/.env.bak", "/.env.save"},
			wantBlockAt: 1,
		},
		{
			name:        "git config sweep, nested under many roots",
			ip:          "34.86.12.72",
			paths:       []string{"/www/.git/config", "/var/www/.git/config", "/public/.git/config"},
			wantBlockAt: 1,
		},
		{
			name:        "wordpress exploit burst",
			ip:          "93.123.109.178",
			paths:       []string{"/blog/wp-json/batch/v1", "/blog//wp-json/batch/v1", "/blog/wp/v2/posts/99999"},
			wantBlockAt: 2,
		},
		{
			name:        "slow php webshell crawl",
			ip:          "158.23.147.79",
			paths:       []string{"/.well-known/pki-validation/xmrlpc.php", "/0x.php", "/1.php", "/NewFile.php", "/about.php"},
			wantBlockAt: 2,
		},
		{
			name:        "php config probing",
			ip:          "45.148.10.62",
			paths:       []string{"/config.php", "/phpinfo.php", "/.env.php", "/test.php"},
			wantBlockAt: 2,
		},
		{
			// A single admin-panel request is not enough. This is the guard
			// against blocking a curious visitor on one stray request.
			name:        "single wp-login probe stays unblocked",
			ip:          "128.90.128.6",
			paths:       []string{"/wp-login.php"},
			wantBlockAt: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestScorer(t)
			blockedAt := 0
			for i, p := range tc.paths {
				d := s.Observe(tc.ip, p)
				if d.JustBlocked && blockedAt == 0 {
					blockedAt = i + 1
				}
			}
			if blockedAt != tc.wantBlockAt {
				t.Fatalf("blocked at request %d, want %d", blockedAt, tc.wantBlockAt)
			}
			if tc.wantBlockAt > 0 {
				if _, ok := s.Blocked(tc.ip); !ok {
					t.Fatal("client should be blocked after the run")
				}
			}
		})
	}
}

// Three admin probes together do cross the threshold: the low tier is not
// useless, it just needs corroboration.
func TestRepeatedAdminProbesEventuallyBlock(t *testing.T) {
	s, _ := newTestScorer(t)
	for _, p := range []string{"/wp-login.php", "/wp-admin/", "/phpmyadmin/"} {
		s.Observe("203.0.113.9", p)
	}
	if _, ok := s.Blocked("203.0.113.9"); !ok {
		t.Fatal("three admin probes should reach the threshold")
	}
}

// MUVON renews its own certificates over this path. Scoring it would let the
// product lock out its own certificate authority.
func TestACMEChallengeIsNeverScored(t *testing.T) {
	s, _ := newTestScorer(t)
	for i := 0; i < 50; i++ {
		d := s.Observe("198.51.100.7", "/.well-known/acme-challenge/tokentokentoken")
		if d.Score != 0 || d.Blocked {
			t.Fatalf("ACME challenge scored %d (blocked=%v)", d.Score, d.Blocked)
		}
	}
}

// The extension alone is never a signal: an appliance install may front a real
// PHP application, and index.php is the front controller of most of them.
func TestOrdinaryPHPFilesAreNotScored(t *testing.T) {
	s, _ := newTestScorer(t)
	for _, p := range []string{"/index.php", "/login.php", "/search.php", "/api/config", "/settings/config"} {
		if d := s.Observe("198.51.100.8", p); d.Score != 0 {
			t.Fatalf("%s scored %d, expected 0", p, d.Score)
		}
	}
}

func TestScoreDecaysOutOfWindow(t *testing.T) {
	s, clock := newTestScorer(t)
	// Two exploit probes would block, but spread them past the window.
	if d := s.Observe("203.0.113.10", "/config.php"); d.Blocked {
		t.Fatal("one exploit probe should not block")
	}
	*clock = clock.Add(7 * time.Hour) // window is 6h
	d := s.Observe("203.0.113.10", "/phpinfo.php")
	if d.Blocked {
		t.Fatal("hits outside the window must not accumulate")
	}
	if d.Score != ScoreExploit {
		t.Fatalf("score = %d, want %d (only the fresh hit)", d.Score, ScoreExploit)
	}
}

func TestRepeatOffenderTTLDoubles(t *testing.T) {
	s, clock := newTestScorer(t)
	ip := "203.0.113.11"

	first := s.Observe(ip, "/.env").Block
	if got := first.ExpiresAt.Sub(first.CreatedAt); got != 15*time.Minute {
		t.Fatalf("first ban = %v, want 15m", got)
	}

	*clock = clock.Add(20 * time.Minute) // let it lapse
	second := s.Observe(ip, "/.env").Block
	if got := second.ExpiresAt.Sub(second.CreatedAt); got != 30*time.Minute {
		t.Fatalf("second ban = %v, want 30m", got)
	}
	if second.BanCount != 2 {
		t.Fatalf("ban count = %d, want 2", second.BanCount)
	}

	*clock = clock.Add(40 * time.Minute)
	third := s.Observe(ip, "/.env").Block
	if got := third.ExpiresAt.Sub(third.CreatedAt); got != time.Hour {
		t.Fatalf("third ban = %v, want 1h", got)
	}
}

func TestTTLLadderStopsAtMax(t *testing.T) {
	s, clock := newTestScorer(t)
	ip := "203.0.113.12"
	var last Block
	for i := 0; i < 15; i++ {
		last = s.Observe(ip, "/.env").Block
		*clock = clock.Add(last.ExpiresAt.Sub(*clock) + time.Minute)
	}
	if got := last.ExpiresAt.Sub(last.CreatedAt); got > 7*24*time.Hour {
		t.Fatalf("ban %v exceeded the 7 day ceiling", got)
	}
}

// A single IPv6 subscriber typically holds a whole /64, so scoring full
// addresses would let one client rotate for free.
func TestIPv6IsScoredPerPrefix(t *testing.T) {
	s, _ := newTestScorer(t)
	// Two different addresses inside the same /64.
	a := "2a00:1880:a28b:216:74eb:8627:74e2:32a0"
	b := "2a00:1880:a28b:216:ffff:1111:2222:3333"

	if d := s.Observe(a, "/config.php"); d.Blocked {
		t.Fatal("first probe should not block")
	}
	d := s.Observe(b, "/phpinfo.php")
	if !d.Blocked {
		t.Fatal("second address in the same /64 must share the score")
	}
	if _, ok := s.Blocked(a); !ok {
		t.Fatal("the whole /64 should be blocked, including the first address")
	}
}

func TestDifferentIPv6PrefixesAreIndependent(t *testing.T) {
	s, _ := newTestScorer(t)
	s.Observe("2a00:1880:a28b:216::1", "/config.php")
	if d := s.Observe("2a00:1880:a28b:999::1", "/phpinfo.php"); d.Blocked {
		t.Fatal("a different /64 must not inherit the score")
	}
}

func TestAllowlistedClientIsNeverBlocked(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	s := New(cfg, []string{"10.0.0.0/24", "203.0.113.50"}, testPatterns(t))
	s.now = func() time.Time { return time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC) }

	for i := 0; i < 20; i++ {
		if d := s.Observe("10.0.0.7", "/.env"); d.Blocked || d.Score != 0 {
			t.Fatal("CIDR allowlisted client must not be scored")
		}
		if d := s.Observe("203.0.113.50", "/.env"); d.Blocked || d.Score != 0 {
			t.Fatal("bare address allowlist entry must not be scored")
		}
	}
}

func TestDisabledScorerDoesNothing(t *testing.T) {
	s := New(DefaultConfig(), nil, testPatterns(t)) // Enabled defaults to false
	for i := 0; i < 10; i++ {
		if d := s.Observe("203.0.113.13", "/.env"); d.Blocked || d.Score != 0 {
			t.Fatal("scorer must be inert while disabled")
		}
	}
}

func TestBlockExpiryReleasesClient(t *testing.T) {
	s, clock := newTestScorer(t)
	ip := "203.0.113.14"
	s.Observe(ip, "/.env")
	if _, ok := s.Blocked(ip); !ok {
		t.Fatal("should be blocked")
	}
	*clock = clock.Add(16 * time.Minute)
	if _, ok := s.Blocked(ip); ok {
		t.Fatal("block should have lapsed")
	}
}

func TestRemoveAndFlush(t *testing.T) {
	s, _ := newTestScorer(t)
	s.Observe("203.0.113.15", "/.env")
	s.Observe("203.0.113.16", "/.env")

	if !s.Remove("203.0.113.15") {
		t.Fatal("Remove should report a lifted block")
	}
	if s.Remove("203.0.113.15") {
		t.Fatal("Remove on a clean client should report false")
	}
	if n := s.Flush(); n != 1 {
		t.Fatalf("Flush cleared %d, want 1", n)
	}
	if len(s.List()) != 0 {
		t.Fatal("list should be empty after flush")
	}
}

// Blocks arriving from central are applied verbatim, and applying the same one
// twice must be harmless because command delivery is at-least-once.
func TestApplyIsIdempotent(t *testing.T) {
	s, clock := newTestScorer(t)
	b := Block{
		Key:       "203.0.113.17",
		Rule:      RuleSecret,
		Pattern:   ".env",
		Score:     100,
		BanCount:  1,
		CreatedAt: *clock,
		ExpiresAt: clock.Add(time.Hour),
	}
	s.Apply(b)
	s.Apply(b)
	if len(s.List()) != 1 {
		t.Fatalf("expected exactly one block, got %d", len(s.List()))
	}
	if _, ok := s.Blocked("203.0.113.17"); !ok {
		t.Fatal("applied block should be in force")
	}
}

func TestPermanentBlockSurvivesExpiry(t *testing.T) {
	s, clock := newTestScorer(t)
	s.Apply(Block{
		Key:       "203.0.113.18",
		Permanent: true,
		CreatedAt: *clock,
		ExpiresAt: clock.Add(time.Minute),
	})
	*clock = clock.Add(48 * time.Hour)
	if _, ok := s.Blocked("203.0.113.18"); !ok {
		t.Fatal("permanent block must ignore expiry")
	}
	s.Sweep()
	if _, ok := s.Blocked("203.0.113.18"); !ok {
		t.Fatal("sweep must not drop a permanent block")
	}
}

func TestSweepDropsExpiredAndIdle(t *testing.T) {
	s, clock := newTestScorer(t)
	s.Observe("203.0.113.19", "/.env")       // blocks
	s.Observe("203.0.113.20", "/config.php") // scores but does not block

	*clock = clock.Add(7 * time.Hour)
	s.Sweep()

	if len(s.List()) != 0 {
		t.Fatal("expired block should be swept")
	}
	s.mu.Lock()
	n := len(s.hits)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("idle score records remain: %d", n)
	}
}

// The tracked-client count is attacker controlled under a distributed scan, so
// the bound has to actually hold.
func TestMaxEntriesBoundsMemory(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.MaxEntries = 50
	s := New(cfg, nil, testPatterns(t))
	clock := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return clock }

	for i := 0; i < 500; i++ {
		clock = clock.Add(time.Second)
		// One scoring hit each, below the threshold, from a distinct address.
		s.Observe(ipv4For(i), "/config.php")
	}
	s.mu.Lock()
	n := len(s.hits)
	s.mu.Unlock()
	if n > cfg.MaxEntries {
		t.Fatalf("tracked %d clients, cap is %d", n, cfg.MaxEntries)
	}
}

func TestKeyNormalisation(t *testing.T) {
	cases := map[string]string{
		"203.0.113.1":                            "203.0.113.1",
		"2a00:1880:a28b:216:74eb:8627:74e2:32a0": "2a00:1880:a28b:216::/64",
		"::ffff:203.0.113.1":                     "203.0.113.1", // v4-mapped collapses to v4
		"not-an-ip":                              "",
		"":                                       "",
	}
	for in, want := range cases {
		if got := Key(in); got != want {
			t.Errorf("Key(%q) = %q, want %q", in, got, want)
		}
	}
}

func ipv4For(i int) string {
	return "198.18." + itoa(i/256) + "." + itoa(i%256)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
