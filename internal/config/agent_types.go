package config

import (
	"strings"
	"time"

	"muvon/internal/db"
)

// AgentPayload is the JSON payload served to agents by the central config API.
type AgentPayload struct {
	Hosts     []db.Host     `json:"hosts"`
	Routes    []db.Route    `json:"routes"`
	Settings  AgentSettings `json:"settings"`
	UpdatedAt string        `json:"updated_at"`
	// Version is an opaque short string identifying this snapshot. Agents
	// echo it back via X-Config-Version on the next pull / SSE reconnect
	// so central can distinguish "agent missed the push" from "agent
	// reapplied an older snapshot".
	Version   string        `json:"version,omitempty"`
}

// AgentSettings is the subset of GlobalConfig that agents need to operate.
type AgentSettings struct {
	LetsEncryptEmail   string `json:"letsencrypt_email"`
	LetsEncryptStaging bool   `json:"letsencrypt_staging"`
	EnableBodyCapture  bool   `json:"enable_body_capture"`
	MaxBodyCaptureSize int    `json:"max_body_capture_size"`

	JWTIdentityEnabled bool     `json:"jwt_identity_enabled"`
	JWTIdentityMode    string   `json:"jwt_identity_mode"`
	JWTClaims          []string `json:"jwt_claims"`
	// JWTSecret is intentionally NOT serialised to agents. JWT identity
	// enrichment happens centrally on diaLOG; agents only forward raw log
	// entries (with the original Authorization header) and never need the
	// signing secret. Sending it would leak a high-value credential to
	// every edge node.
	JWTSecret          string   `json:"-"`

	GeoIPEnabled bool   `json:"geoip_enabled"`
	GeoIPDBPath  string `json:"geoip_db_path"`
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
			}
		}
	}
	return AgentPayload{
		Hosts:     hosts,
		Routes:    routes,
		Settings:  globalToAgentSettings(cfg.Global),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// ToConfig converts an AgentPayload back to the in-memory Config representation.
func (p AgentPayload) ToConfig() *Config {
	cfg := &Config{Hosts: make(map[string]*HostConfig)}

	routesByHost := make(map[int][]db.Route)
	for _, r := range p.Routes {
		routesByHost[r.HostID] = append(routesByHost[r.HostID], r)
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
			hc.Routes = append(hc.Routes, RouteRule{
				Route:      r,
				PathPrefix: r.PathPrefix,
			})
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

		JWTIdentityEnabled: g.JWTIdentityEnabled,
		JWTIdentityMode:    g.JWTIdentityMode,
		JWTClaims:          g.JWTClaims,
		// JWTSecret deliberately omitted from the agent payload — see the
		// json:"-" tag on AgentSettings.JWTSecret for reasoning.

		GeoIPEnabled: g.GeoIPEnabled,
		GeoIPDBPath:  g.GeoIPDBPath,
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

		JWTIdentityEnabled: s.JWTIdentityEnabled,
		JWTIdentityMode:    s.JWTIdentityMode,
		JWTClaims:          claims,
		// JWTSecret is never populated agent-side — central holds the secret.

		GeoIPEnabled: s.GeoIPEnabled,
		GeoIPDBPath:  s.GeoIPDBPath,
	}
}
