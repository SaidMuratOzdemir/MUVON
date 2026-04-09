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
}

// AgentSettings is the subset of GlobalConfig that agents need to operate.
type AgentSettings struct {
	LetsEncryptEmail   string `json:"letsencrypt_email"`
	LetsEncryptStaging bool   `json:"letsencrypt_staging"`
	EnableBodyCapture  bool   `json:"enable_body_capture"`
	MaxBodyCaptureSize int    `json:"max_body_capture_size"`

	WafEnabledGlobal           bool    `json:"waf_enabled_global"`
	WafDetectionOnly           bool    `json:"waf_detection_only"`
	WafScoreThresholdLog       int     `json:"waf_score_threshold_log"`
	WafScoreThresholdRateLimit int     `json:"waf_score_threshold_ratelimit"`
	WafScoreThresholdBlock     int     `json:"waf_score_threshold_block"`
	WafScoreThresholdTempBan   int     `json:"waf_score_threshold_tempban"`
	WafScoreThresholdBan       int     `json:"waf_score_threshold_ban"`
	WafIPScoreDecayPerHour     float64 `json:"waf_ip_score_decay_per_hour"`
	WafIPScoreWindowHours      int     `json:"waf_ip_score_window_hours"`
	WafTempBanDurationMinutes  int     `json:"waf_tempban_duration_minutes"`
	WafPatternCacheTTLSeconds  int     `json:"waf_pattern_cache_ttl_seconds"`
	WafVTApiKey                string  `json:"waf_vt_api_key"`
	WafVTTimeoutSeconds        int     `json:"waf_vt_timeout_seconds"`
	WafVTCacheTTLHours         int     `json:"waf_vt_cache_ttl_hours"`
	WafVTScoreContribution     int     `json:"waf_vt_score_contribution"`
	WafMaxBodyInspectBytes     int     `json:"waf_max_body_inspect_bytes"`
	WafNormalizationMaxIter    int     `json:"waf_normalization_max_iterations"`

	JWTIdentityEnabled bool     `json:"jwt_identity_enabled"`
	JWTIdentityMode    string   `json:"jwt_identity_mode"`
	JWTClaims          []string `json:"jwt_claims"`
	JWTSecret          string   `json:"jwt_secret"`

	GeoIPEnabled bool   `json:"geoip_enabled"`
	GeoIPDBPath  string `json:"geoip_db_path"`
}

// AgentPayloadFromConfig builds an AgentPayload from the current in-memory config.
func AgentPayloadFromConfig(cfg *Config) AgentPayload {
	var hosts []db.Host
	var routes []db.Route
	for _, hc := range cfg.Hosts {
		hosts = append(hosts, hc.Host)
		for _, rr := range hc.Routes {
			routes = append(routes, rr.Route)
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

		WafEnabledGlobal:           g.WafEnabledGlobal,
		WafDetectionOnly:           g.WafDetectionOnly,
		WafScoreThresholdLog:       g.WafScoreThresholdLog,
		WafScoreThresholdRateLimit: g.WafScoreThresholdRateLimit,
		WafScoreThresholdBlock:     g.WafScoreThresholdBlock,
		WafScoreThresholdTempBan:   g.WafScoreThresholdTempBan,
		WafScoreThresholdBan:       g.WafScoreThresholdBan,
		WafIPScoreDecayPerHour:     g.WafIPScoreDecayPerHour,
		WafIPScoreWindowHours:      g.WafIPScoreWindowHours,
		WafTempBanDurationMinutes:  g.WafTempBanDurationMinutes,
		WafPatternCacheTTLSeconds:  g.WafPatternCacheTTLSeconds,
		WafVTApiKey:                g.WafVTApiKey,
		WafVTTimeoutSeconds:        g.WafVTTimeoutSeconds,
		WafVTCacheTTLHours:         g.WafVTCacheTTLHours,
		WafVTScoreContribution:     g.WafVTScoreContribution,
		WafMaxBodyInspectBytes:     g.WafMaxBodyInspectBytes,
		WafNormalizationMaxIter:    g.WafNormalizationMaxIter,

		JWTIdentityEnabled: g.JWTIdentityEnabled,
		JWTIdentityMode:    g.JWTIdentityMode,
		JWTClaims:          g.JWTClaims,
		JWTSecret:          g.JWTSecret,

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

		WafEnabledGlobal:           s.WafEnabledGlobal,
		WafDetectionOnly:           s.WafDetectionOnly,
		WafScoreThresholdLog:       s.WafScoreThresholdLog,
		WafScoreThresholdRateLimit: s.WafScoreThresholdRateLimit,
		WafScoreThresholdBlock:     s.WafScoreThresholdBlock,
		WafScoreThresholdTempBan:   s.WafScoreThresholdTempBan,
		WafScoreThresholdBan:       s.WafScoreThresholdBan,
		WafIPScoreDecayPerHour:     s.WafIPScoreDecayPerHour,
		WafIPScoreWindowHours:      s.WafIPScoreWindowHours,
		WafTempBanDurationMinutes:  s.WafTempBanDurationMinutes,
		WafPatternCacheTTLSeconds:  s.WafPatternCacheTTLSeconds,
		WafVTApiKey:                s.WafVTApiKey,
		WafVTTimeoutSeconds:        s.WafVTTimeoutSeconds,
		WafVTCacheTTLHours:         s.WafVTCacheTTLHours,
		WafVTScoreContribution:     s.WafVTScoreContribution,
		WafMaxBodyInspectBytes:     s.WafMaxBodyInspectBytes,
		WafNormalizationMaxIter:    s.WafNormalizationMaxIter,

		JWTIdentityEnabled: s.JWTIdentityEnabled,
		JWTIdentityMode:    s.JWTIdentityMode,
		JWTClaims:          claims,
		JWTSecret:          s.JWTSecret,

		GeoIPEnabled: s.GeoIPEnabled,
		GeoIPDBPath:  s.GeoIPDBPath,
	}
}
