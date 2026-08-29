package config

import (
	"testing"
	"time"

	"muvon/internal/blocklist"
	"muvon/internal/db"
)

// Anything the proxy reads from Config has to survive the trip to an agent. A
// field the payload does not carry takes its zero value there, which for a
// feature flag reads as "off" and raises no error, so the assertion has to be
// explicit.
func TestAgentPayloadCarriesBlocking(t *testing.T) {
	agentID := "agent-1"
	targetKind := "agent"

	cfg := &Config{
		Hosts: map[string]*HostConfig{
			"shop.example.com": {
				Host: db.Host{
					ID: 1, Domain: "shop.example.com", IsActive: true,
					TargetKind: targetKind, TargetAgentID: &agentID,
				},
			},
		},
		Blocking: BlockingConfig{
			Settings: db.BlocklistSettings{
				Enabled:    true,
				Threshold:  30,
				Window:     6 * time.Hour,
				BaseTTL:    15 * time.Minute,
				MaxTTL:     7 * 24 * time.Hour,
				MaxEntries: 100000,
				Allowlist:  []string{"10.0.0.0/24"},
			},
			Patterns: []blocklist.Pattern{
				{Kind: blocklist.KindFilename, Pattern: ".env", Score: 100,
					Rule: blocklist.RuleSecret, Enabled: true, Builtin: true},
			},
			Active: []blocklist.Block{
				{Key: "203.0.113.7", Rule: blocklist.RuleSecret, Pattern: ".env",
					Score: 100, BanCount: 1,
					CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
			},
		},
	}

	got := AgentPayloadFromConfig(cfg, agentID).ToConfig()

	s := got.Blocking.Settings
	if !s.Enabled {
		t.Error("blocking arrived disabled")
	}
	if s.Threshold != 30 {
		t.Errorf("threshold = %d, want 30", s.Threshold)
	}
	if s.Window != 6*time.Hour {
		t.Errorf("window = %v, want 6h", s.Window)
	}
	if s.BaseTTL != 15*time.Minute {
		t.Errorf("base ttl = %v, want 15m", s.BaseTTL)
	}
	if s.MaxTTL != 7*24*time.Hour {
		t.Errorf("max ttl = %v, want 168h", s.MaxTTL)
	}
	if s.MaxEntries != 100000 {
		t.Errorf("max entries = %d, want 100000", s.MaxEntries)
	}
	if len(s.Allowlist) != 1 || s.Allowlist[0] != "10.0.0.0/24" {
		t.Errorf("allowlist = %v, want [10.0.0.0/24]", s.Allowlist)
	}

	if len(got.Blocking.Patterns) != 1 || got.Blocking.Patterns[0].Pattern != ".env" {
		t.Fatalf("patterns did not survive: %+v", got.Blocking.Patterns)
	}
	if len(got.Blocking.Active) != 1 || got.Blocking.Active[0].Key != "203.0.113.7" {
		t.Fatalf("active blocks did not survive: %+v", got.Blocking.Active)
	}
}

// Patterns that reach an agent must still compile there, so the edge enforces
// the same rule set the panel shows.
func TestAgentPatternsStillCompile(t *testing.T) {
	cfg := &Config{
		Hosts:    map[string]*HostConfig{},
		Blocking: BlockingConfig{Patterns: blocklist.DefaultPatterns()},
	}
	got := AgentPayloadFromConfig(cfg, "agent-1").ToConfig()

	set, errs := blocklist.Compile(got.Blocking.Patterns)
	if len(errs) > 0 {
		t.Fatalf("patterns failed to compile after the round trip: %v", errs)
	}
	if set.Empty() {
		t.Fatal("compiled set is empty")
	}
	if m := set.Score("/.env"); m.Score == 0 {
		t.Error("a credential probe scores zero on the agent side")
	}
}

// An agent talking to a central that predates blocking gets no blocking block
// at all. It must then run with the feature off rather than with a half filled
// configuration that blocks on a zero threshold.
func TestAgentPayloadWithoutBlockingIsInert(t *testing.T) {
	p := AgentPayload{Hosts: []db.Host{}}
	cfg := p.ToConfig()

	if cfg.Blocking.Settings.Enabled {
		t.Error("blocking must default to off when central did not send it")
	}
	if len(cfg.Blocking.Patterns) != 0 {
		t.Error("no patterns should be present")
	}
}
