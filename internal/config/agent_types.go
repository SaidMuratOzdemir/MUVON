package config

import (
	"strings"
	"time"

	"muvon/internal/blocklist"
	"muvon/internal/db"
)

// AgentPayload is the JSON payload served to agents by the central config API.
type AgentPayload struct {
	Hosts     []db.Host     `json:"hosts"`
	Routes    []db.Route    `json:"routes"`
	Settings  AgentSettings `json:"settings"`
	UpdatedAt string        `json:"updated_at"`
	// ManagedBackends carries the active container endpoints for every
	// managed component referenced by Routes. Without this the agent's
	// proxy can match a route but has no URL to dial, and ServeHTTP
	// fails with "no backend configured". Central knows the list
	// because the deployer reports instance lifecycle to it.
	ManagedBackends []db.ManagedBackend `json:"managed_backends,omitempty"`
	// ExtraMounts is the operator-defined list of host bind-mount paths
	// the agent should expose to its container (read-only). The agent
	// stores this list in memory and threads it into the helper
	// container when agent.self_upgrade rewrites compose. UI-managed;
	// initial install can still pass --mount on install-agent.sh but
	// the source of truth is the agents.extra_mounts column.
	ExtraMounts []string `json:"extra_mounts,omitempty"`
	// Blocking carries the edge blocking surface: thresholds, patterns and
	// the blocks central has already decided. The agent scores requests
	// itself, so the decision needs these values on the machine that
	// terminates the traffic rather than only on central.
	Blocking *AgentBlocking `json:"blocking,omitempty"`
	// Version is an opaque short string identifying this snapshot. Agents
	// echo it back via X-Config-Version on the next pull / SSE reconnect
	// so central can distinguish "agent missed the push" from "agent
	// reapplied an older snapshot".
	Version string `json:"version,omitempty"`
}

// AgentSettings is the subset of GlobalConfig that agents need to operate.
type AgentSettings struct {
	LetsEncryptEmail   string `json:"letsencrypt_email"`
	LetsEncryptStaging bool   `json:"letsencrypt_staging"`
	EnableBodyCapture  bool   `json:"enable_body_capture"`
	MaxBodyCaptureSize int    `json:"max_body_capture_size"`

	RUMSampleRate    float64 `json:"rum_sample_rate"`
	RUMMaxBatchBytes int     `json:"rum_max_batch_bytes"`

	JWTIdentityEnabled bool     `json:"jwt_identity_enabled"`
	JWTIdentityMode    string   `json:"jwt_identity_mode"`
	JWTClaims          []string `json:"jwt_claims"`
	// JWTSecret is intentionally NOT serialised to agents. JWT identity
	// enrichment happens centrally on diaLOG; agents only forward raw log
	// entries (with the original Authorization header) and never need the
	// signing secret. Sending it would leak a high-value credential to
	// every edge node.
	JWTSecret string `json:"-"`
}

// AgentBlocking is the wire form of the edge blocking surface. Agents score
// with exactly the patterns and thresholds central is using, so a scanner that
// walks the fleet meets the same rules everywhere.
type AgentBlocking struct {
	Enabled    bool     `json:"enabled"`
	Threshold  int      `json:"threshold"`
	WindowSec  int      `json:"window_seconds"`
	TTLSec     int      `json:"ttl_seconds"`
	TTLMaxSec  int      `json:"ttl_max_seconds"`
	MaxEntries int      `json:"max_entries"`
	Allowlist  []string `json:"allowlist,omitempty"`

	Patterns []blocklist.Pattern `json:"patterns,omitempty"`
	// Active is what central has already decided, so an agent that has never
	// seen the offender still refuses it.
	Active []blocklist.Block `json:"active,omitempty"`
}

// AgentPayloadFromConfig builds an AgentPayload tailored to a specific
// agent. Only hosts whose target_kind="agent" and target_agent_id matches
// agentID are emitted, along with the routes that bind to them. Central
// hosts and hosts bound to a different agent stay out of this payload —
// that's what stops the wrong instance from silently terminating traffic
// or trying to issue a certificate for a domain it doesn't own.
//
// Passing an empty agentID returns an empty payload (no agent ever runs
// without an ID).
func AgentPayloadFromConfig(cfg *Config, agentID string) AgentPayload {
	var hosts []db.Host
	var routes []db.Route
	// dedupe managed backends across overlapping routes (same component
	// can serve multiple routes on the same host).
	backendsByID := map[string]db.ManagedBackend{}
	if agentID != "" {
		for _, hc := range cfg.Hosts {
			if hc.Host.TargetKind != "agent" {
				continue
			}
			if hc.Host.TargetAgentID == nil || *hc.Host.TargetAgentID != agentID {
				continue
			}
			hosts = append(hosts, hc.Host)
			for _, rr := range hc.Routes {
				routes = append(routes, rr.Route)
				for _, b := range rr.ManagedBackends {
					backendsByID[b.InstanceID] = b
				}
			}
		}
	}
	managed := make([]db.ManagedBackend, 0, len(backendsByID))
	for _, b := range backendsByID {
		managed = append(managed, b)
	}
	bs := cfg.Blocking.Settings
	return AgentPayload{
		Hosts:           hosts,
		Routes:          routes,
		Settings:        globalToAgentSettings(cfg.Global),
		ManagedBackends: managed,
		Blocking: &AgentBlocking{
			Enabled:    bs.Enabled,
			Threshold:  bs.Threshold,
			WindowSec:  int(bs.Window / time.Second),
			TTLSec:     int(bs.BaseTTL / time.Second),
			TTLMaxSec:  int(bs.MaxTTL / time.Second),
			MaxEntries: bs.MaxEntries,
			Allowlist:  bs.Allowlist,
			Patterns:   cfg.Blocking.Patterns,
			Active:     cfg.Blocking.Active,
		},
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// ToConfig converts an AgentPayload back to the in-memory Config representation.
func (p AgentPayload) ToConfig() *Config {
	cfg := &Config{Hosts: make(map[string]*HostConfig)}

	// A payload from a central that predates blocking leaves this nil, and the
	// agent then runs with blocking off rather than with half a configuration.
	if p.Blocking != nil {
		cfg.Blocking = BlockingConfig{
			Settings: db.BlocklistSettings{
				Enabled:    p.Blocking.Enabled,
				Threshold:  p.Blocking.Threshold,
				Window:     time.Duration(p.Blocking.WindowSec) * time.Second,
				BaseTTL:    time.Duration(p.Blocking.TTLSec) * time.Second,
				MaxTTL:     time.Duration(p.Blocking.TTLMaxSec) * time.Second,
				MaxEntries: p.Blocking.MaxEntries,
				Allowlist:  p.Blocking.Allowlist,
			},
			Patterns: p.Blocking.Patterns,
			Active:   p.Blocking.Active,
		}
	}

	routesByHost := make(map[int][]db.Route)
	for _, r := range p.Routes {
		routesByHost[r.HostID] = append(routesByHost[r.HostID], r)
	}
	// Backends grouped by component so each managed-proxy route can
	// resolve to the round-robin pool the deployer populated on central.
	backendsByComponent := make(map[int][]db.ManagedBackend)
	for _, b := range p.ManagedBackends {
		backendsByComponent[b.ComponentID] = append(backendsByComponent[b.ComponentID], b)
	}

	for _, h := range p.Hosts {
		if !h.IsActive {
			continue
		}
		hc := &HostConfig{Host: h}
		for _, r := range routesByHost[h.ID] {
			if !r.IsActive {
				continue
			}
			rule := RouteRule{
				Route:      r,
				PathPrefix: r.PathPrefix,
			}
			if r.ManagedComponentID != nil {
				rule.ManagedBackends = backendsByComponent[*r.ManagedComponentID]
			}
			hc.Routes = append(hc.Routes, rule)
		}
		// Per-host JWT metadata crosses the wire via db.Host's json tags.
		// The secret itself is json:"-" on purpose — agents never receive
		// it because enrichment happens centrally. The metadata is carried
		// so agents stay consistent with the central snapshot.
		hc.JWTIdentityEnabled = h.JWTIdentityEnabled
		hc.JWTIdentityMode = h.JWTIdentityMode
		if h.JWTClaims != "" {
			hc.JWTClaims = strings.Split(h.JWTClaims, ",")
			for i, c := range hc.JWTClaims {
				hc.JWTClaims[i] = strings.TrimSpace(c)
			}
		}
		cfg.Hosts[h.Domain] = hc
	}

	cfg.Global = agentSettingsToGlobal(p.Settings)
	return cfg
}

func globalToAgentSettings(g GlobalConfig) AgentSettings {
	return AgentSettings{
		LetsEncryptEmail:   g.LetsEncryptEmail,
		LetsEncryptStaging: g.LetsEncryptStaging,
		EnableBodyCapture:  g.EnableBodyCapture,
		MaxBodyCaptureSize: g.MaxBodyCaptureSize,

		RUMSampleRate:    g.RUMSampleRate,
		RUMMaxBatchBytes: g.RUMMaxBatchBytes,

		JWTIdentityEnabled: g.JWTIdentityEnabled,
		JWTIdentityMode:    g.JWTIdentityMode,
		JWTClaims:          g.JWTClaims,
		// JWTSecret deliberately omitted from the agent payload — see the
		// json:"-" tag on AgentSettings.JWTSecret for reasoning.
	}
}

func agentSettingsToGlobal(s AgentSettings) GlobalConfig {
	var claims []string
	for _, c := range s.JWTClaims {
		if t := strings.TrimSpace(c); t != "" {
			claims = append(claims, t)
		}
	}
	return GlobalConfig{
		LetsEncryptEmail:   s.LetsEncryptEmail,
		LetsEncryptStaging: s.LetsEncryptStaging,
		EnableBodyCapture:  s.EnableBodyCapture,
		MaxBodyCaptureSize: s.MaxBodyCaptureSize,

		RUMSampleRate:    s.RUMSampleRate,
		RUMMaxBatchBytes: s.RUMMaxBatchBytes,

		JWTIdentityEnabled: s.JWTIdentityEnabled,
		JWTIdentityMode:    s.JWTIdentityMode,
		JWTClaims:          claims,
		// JWTSecret is never populated agent-side — central holds the secret.
	}
}
