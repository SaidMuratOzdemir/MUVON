package config

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"muvon/internal/db"
	"muvon/internal/secret"
)

type Config struct {
	Hosts  map[string]*HostConfig // domain -> config
	Global GlobalConfig
}

type HostConfig struct {
	Host   db.Host
	Routes []RouteRule
}

type RouteRule struct {
	Route      db.Route
	PathPrefix string
}

type GlobalConfig struct {
	RetentionDays      int
	MaxBodyCaptureSize int
	LogPipelineBuffer  int
	LogBatchSize       int
	LogFlushIntervalMs int
	LogWorkerCount     int
	EnableBodyCapture  bool
	LetsEncryptStaging bool
	LetsEncryptEmail   string
	WafURL             string // deprecated: kept for migration compatibility
	WafTimeoutMs       int    // deprecated: kept for migration compatibility

	// WAF Engine settings
	WafEnabledGlobal          bool
	WafDetectionOnly          bool
	WafScoreThresholdLog      int
	WafScoreThresholdRateLimit int
	WafScoreThresholdBlock    int
	WafScoreThresholdTempBan  int
	WafScoreThresholdBan      int
	WafIPScoreDecayPerHour    float64
	WafIPScoreWindowHours     int
	WafTempBanDurationMinutes int
	WafPatternCacheTTLSeconds int
	WafVTApiKey               string
	WafVTTimeoutSeconds       int
	WafVTCacheTTLHours        int
	WafVTScoreContribution    int
	WafMaxBodyInspectBytes    int
	WafNormalizationMaxIter   int

	// JWT Identity settings
	JWTIdentityEnabled bool
	JWTIdentityMode    string   // "verify" or "decode"
	JWTClaims          []string // claim keys to extract
	JWTSecret          string   // HS256 secret (write-only in UI)

	// GeoIP settings
	GeoIPEnabled bool
	GeoIPDBPath  string

	// Alerting settings
	AlertingEnabled         bool
	AlertingSlackWebhook    string
	AlertingSMTPHost        string
	AlertingSMTPPort        int
	AlertingSMTPUsername    string
	AlertingSMTPPassword    string
	AlertingSMTPFrom        string
	AlertingSMTPTo          string
	AlertingCooldownSeconds int
}

func LoadFromDB(ctx context.Context, database *db.DB, box *secret.Box) (*Config, error) {
	hosts, routeMap, err := database.LoadActiveRoutes(ctx)
	if err != nil {
		return nil, fmt.Errorf("config: load routes: %w", err)
	}

	cfg := &Config{
		Hosts: make(map[string]*HostConfig, len(hosts)),
	}

	for _, h := range hosts {
		hc := &HostConfig{Host: h}
		for _, r := range routeMap[h.ID] {
			hc.Routes = append(hc.Routes, RouteRule{
				Route:      r,
				PathPrefix: r.PathPrefix,
			})
		}
		cfg.Hosts[h.Domain] = hc
	}

	cfg.Global, err = loadGlobalConfig(ctx, database, box)
	if err != nil {
		return nil, err
	}

	slog.Info("config loaded", "hosts", len(cfg.Hosts))
	return cfg, nil
}

func loadGlobalConfig(ctx context.Context, database *db.DB, box *secret.Box) (GlobalConfig, error) {
	settings, err := database.GetAllSettings(ctx)
	if err != nil {
		return GlobalConfig{}, fmt.Errorf("config: load settings: %w", err)
	}

	g := GlobalConfig{
		RetentionDays:      30,
		MaxBodyCaptureSize: 65536,
		LogPipelineBuffer:  10000,
		LogBatchSize:       1000,
		LogFlushIntervalMs: 2000,
		LogWorkerCount:     4,
		EnableBodyCapture:  true,
		LetsEncryptStaging: false,
		WafTimeoutMs:       200,
	}

	g.RetentionDays = getIntSetting(settings, "retention_days", g.RetentionDays)
	g.MaxBodyCaptureSize = getIntSetting(settings, "max_body_capture_size", g.MaxBodyCaptureSize)
	g.LogPipelineBuffer = getIntSetting(settings, "log_pipeline_buffer", g.LogPipelineBuffer)
	g.LogBatchSize = getIntSetting(settings, "log_batch_size", g.LogBatchSize)
	g.LogFlushIntervalMs = getIntSetting(settings, "log_flush_interval_ms", g.LogFlushIntervalMs)
	g.LogWorkerCount = getIntSetting(settings, "log_worker_count", g.LogWorkerCount)
	g.EnableBodyCapture = getBoolSetting(settings, "enable_body_capture", g.EnableBodyCapture)
	g.LetsEncryptStaging = getBoolSetting(settings, "letsencrypt_staging", g.LetsEncryptStaging)
	g.LetsEncryptEmail = getStrSetting(settings, "letsencrypt_email", g.LetsEncryptEmail)
	g.WafURL = getStrSetting(settings, "waf_url", g.WafURL)
	g.WafTimeoutMs = getIntSetting(settings, "waf_timeout_ms", g.WafTimeoutMs)

	// WAF Engine settings
	g.WafEnabledGlobal = getBoolSetting(settings, "waf_enabled_global", true)
	g.WafDetectionOnly = getBoolSetting(settings, "waf_detection_only", false)
	g.WafScoreThresholdLog = getIntSetting(settings, "waf_score_threshold_log", 0)
	g.WafScoreThresholdRateLimit = getIntSetting(settings, "waf_score_threshold_ratelimit", 11)
	g.WafScoreThresholdBlock = getIntSetting(settings, "waf_score_threshold_block", 26)
	g.WafScoreThresholdTempBan = getIntSetting(settings, "waf_score_threshold_tempban", 51)
	g.WafScoreThresholdBan = getIntSetting(settings, "waf_score_threshold_ban", 101)
	g.WafIPScoreDecayPerHour = getFloatSetting(settings, "waf_ip_score_decay_per_hour", 5.0)
	g.WafIPScoreWindowHours = getIntSetting(settings, "waf_ip_score_window_hours", 24)
	g.WafTempBanDurationMinutes = getIntSetting(settings, "waf_tempban_duration_minutes", 60)
	g.WafPatternCacheTTLSeconds = getIntSetting(settings, "waf_pattern_cache_ttl_seconds", 60)
	g.WafVTApiKey = getStrSetting(settings, "waf_vt_api_key", "")
	g.WafVTTimeoutSeconds = getIntSetting(settings, "waf_vt_timeout_seconds", 8)
	g.WafVTCacheTTLHours = getIntSetting(settings, "waf_vt_cache_ttl_hours", 24)
	g.WafVTScoreContribution = getIntSetting(settings, "waf_vt_score_contribution", 30)
	g.WafMaxBodyInspectBytes = getIntSetting(settings, "waf_max_body_inspect_bytes", 65536)
	g.WafNormalizationMaxIter = getIntSetting(settings, "waf_normalization_max_iterations", 3)

	// JWT Identity
	g.JWTIdentityEnabled = getBoolSetting(settings, "jwt_identity_enabled", false)
	g.JWTIdentityMode = getStrSetting(settings, "jwt_identity_mode", "verify")
	claimsStr := getStrSetting(settings, "jwt_claims", "sub,email,name,role")
	if claimsStr != "" {
		g.JWTClaims = splitClaims(claimsStr)
	}
	g.JWTSecret = decryptSetting(box, getStrSetting(settings, "jwt_secret", ""), "jwt_secret")

	// GeoIP
	g.GeoIPEnabled = getBoolSetting(settings, "geoip_enabled", false)
	g.GeoIPDBPath = getStrSetting(settings, "geoip_db_path", "")

	// Alerting
	g.AlertingEnabled = getBoolSetting(settings, "alerting_enabled", false)
	g.AlertingSlackWebhook = getStrSetting(settings, "alerting_slack_webhook", "")
	g.AlertingSMTPHost = getStrSetting(settings, "alerting_smtp_host", "")
	g.AlertingSMTPPort = getIntSetting(settings, "alerting_smtp_port", 587)
	g.AlertingSMTPUsername = getStrSetting(settings, "alerting_smtp_username", "")
	g.AlertingSMTPPassword = decryptSetting(box, getStrSetting(settings, "alerting_smtp_password", ""), "alerting_smtp_password")
	g.AlertingSMTPFrom = getStrSetting(settings, "alerting_smtp_from", "")
	g.AlertingSMTPTo = getStrSetting(settings, "alerting_smtp_to", "")
	g.AlertingCooldownSeconds = getIntSetting(settings, "alerting_cooldown_seconds", 300)

	return g, nil
}

func splitClaims(s string) []string {
	var claims []string
	for _, part := range strings.Split(s, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			claims = append(claims, trimmed)
		}
	}
	return claims
}

func (g GlobalConfig) FlushInterval() time.Duration {
	return time.Duration(g.LogFlushIntervalMs) * time.Millisecond
}

// WafSettings is a plain struct used to pass WAF config to the WAF engine
// without creating an import cycle.
type WafSettings struct {
	EnabledGlobal          bool
	DetectionOnly          bool
	ThresholdLog           int
	ThresholdRateLimit     int
	ThresholdBlock         int
	ThresholdTempBan       int
	ThresholdBan           int
	IPScoreDecayPerHour    float64
	IPScoreWindowHours     int
	TempBanDurationMinutes int
	PatternCacheTTLSeconds int
	VTApiKey               string
	VTTimeoutSeconds       int
	VTCacheTTLHours        int
	VTScoreContribution    int
	MaxBodyInspectBytes    int
	NormalizationMaxIter   int
}

// ExtractWafSettings converts GlobalConfig WAF fields to WafSettings.
func (g GlobalConfig) ExtractWafSettings() WafSettings {
	return WafSettings{
		EnabledGlobal:          g.WafEnabledGlobal,
		DetectionOnly:          g.WafDetectionOnly,
		ThresholdLog:           g.WafScoreThresholdLog,
		ThresholdRateLimit:     g.WafScoreThresholdRateLimit,
		ThresholdBlock:         g.WafScoreThresholdBlock,
		ThresholdTempBan:       g.WafScoreThresholdTempBan,
		ThresholdBan:           g.WafScoreThresholdBan,
		IPScoreDecayPerHour:    g.WafIPScoreDecayPerHour,
		IPScoreWindowHours:     g.WafIPScoreWindowHours,
		TempBanDurationMinutes: g.WafTempBanDurationMinutes,
		PatternCacheTTLSeconds: g.WafPatternCacheTTLSeconds,
		VTApiKey:               g.WafVTApiKey,
		VTTimeoutSeconds:       g.WafVTTimeoutSeconds,
		VTCacheTTLHours:        g.WafVTCacheTTLHours,
		VTScoreContribution:    g.WafVTScoreContribution,
		MaxBodyInspectBytes:    g.WafMaxBodyInspectBytes,
		NormalizationMaxIter:   g.WafNormalizationMaxIter,
	}
}

func getIntSetting(m map[string]json.RawMessage, key string, def int) int {
	raw, ok := m[key]
	if !ok {
		return def
	}
	s := unquoteJSON(raw)
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}

func getBoolSetting(m map[string]json.RawMessage, key string, def bool) bool {
	raw, ok := m[key]
	if !ok {
		return def
	}
	s := unquoteJSON(raw)
	v, err := strconv.ParseBool(s)
	if err != nil {
		return def
	}
	return v
}

func getFloatSetting(m map[string]json.RawMessage, key string, def float64) float64 {
	raw, ok := m[key]
	if !ok {
		return def
	}
	s := unquoteJSON(raw)
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return def
	}
	return v
}

func getStrSetting(m map[string]json.RawMessage, key string, def string) string {
	raw, ok := m[key]
	if !ok {
		return def
	}
	return unquoteJSON(raw)
}

func unquoteJSON(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return string(raw)
	}
	return s
}

// decryptSetting decrypts a secret value using the provided Box.
// If decryption fails (wrong key, corrupted data), logs a warning and returns
// empty string so the feature is disabled rather than crashing or leaking ciphertext.
func decryptSetting(box *secret.Box, value, key string) string {
	if value == "" {
		return ""
	}
	plain, err := box.Decrypt(value)
	if err != nil {
		slog.Warn("failed to decrypt setting, feature will be disabled", "key", key, "error", err)
		return ""
	}
	return plain
}
