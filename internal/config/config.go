package config

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
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

	// Decrypted per-host JWT identity config. When JWTIdentityEnabled is
	// false the pipeline must fall back to the GlobalConfig equivalents —
	// this struct always reflects ONLY this host's declared overrides.
	// Secret is the plaintext; callers must not serialise it.
	JWTIdentityEnabled bool
	JWTIdentityMode    string
	JWTClaims          []string
	JWTSecret          string
}

type RouteRule struct {
	Route           db.Route
	PathPrefix      string
	ManagedBackends []db.ManagedBackend
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
	WafEnabledGlobal           bool
	WafDetectionOnly           bool
	WafScoreThresholdLog       int
	WafScoreThresholdRateLimit int
	WafScoreThresholdBlock     int
	WafScoreThresholdTempBan   int
	WafScoreThresholdBan       int
	WafIPScoreDecayPerHour     float64
	WafIPScoreWindowHours      int
	WafTempBanDurationMinutes  int
	WafPatternCacheTTLSeconds  int
	WafVTApiKey                string
	WafVTTimeoutSeconds        int
	WafVTCacheTTLHours         int
	WafVTScoreContribution     int
	WafMaxBodyInspectBytes     int
	WafNormalizationMaxIter    int

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

	// Correlation engine — every threshold and path list is editable live
	// so ops can tune detection to the protected app's traffic shape.
	Correlation CorrelationConfig
}

// CorrelationConfig parametrizes every rule in the correlation engine.
// Regexes and duration-typed windows are pre-computed once per config reload
// so the hot path never pays their parse cost.
type CorrelationConfig struct {
	// Path scan: N distinct 404 paths from the same IP in a window.
	PathScanDistinct int
	PathScanWindow   time.Duration

	// Auth brute force: N auth failures from the same IP in a window.
	// Django / simplejwt apps return 400 on bad credentials rather than 401,
	// so the rule also treats 400 as a failure when the request path matches
	// one of the configured login paths.
	AuthBruteCount  int
	AuthBruteWindow time.Duration
	AuthPaths       []string // exact or prefix-match login endpoints

	// WAF repeat offender: N WAF blocks from the same IP in a window.
	WafRepeatCount  int
	WafRepeatWindow time.Duration

	// Error spike: N 5xx responses for the same host in a window.
	// Previously fired on every single 5xx with no cooldown, which could
	// flood Slack during an outage — now rate-limited via normal cooldown.
	ErrorSpikeCount  int
	ErrorSpikeWindow time.Duration

	// Host-wide traffic anomaly: compares current RPS to a baseline and
	// alerts when the ratio exceeds the threshold. MinBaseline filters out
	// low-traffic hosts where 1 → 10 requests would look like a 10× spike.
	AnomalyEnabled     bool
	AnomalyRatio       float64
	AnomalyBaseline    time.Duration
	AnomalyCurrent     time.Duration
	AnomalyMinBaseline int

	// Sensitive access: app-specific high-value paths. When requests to any
	// of the glob-matched paths exceed Threshold inside Window, alert.
	// Empty SensitivePaths disables the rule.
	SensitivePaths     []string // globs, matched with path.Match
	SensitiveThreshold int
	SensitiveWindow    time.Duration

	// Data export burst: per-user export/download volume. ExportPattern is
	// compiled once; if nil the rule is disabled.
	ExportPattern   *regexp.Regexp
	ExportThreshold int
	ExportWindow    time.Duration
}

func LoadFromDB(ctx context.Context, database *db.DB, box *secret.Box) (*Config, error) {
	hosts, routeMap, err := database.LoadActiveRoutes(ctx)
	if err != nil {
		return nil, fmt.Errorf("config: load routes: %w", err)
	}

	cfg := &Config{
		Hosts: make(map[string]*HostConfig, len(hosts)),
	}

	managedBackends, err := database.ListActiveManagedBackends(ctx)
	if err != nil {
		return nil, fmt.Errorf("config: load managed backends: %w", err)
	}

	for _, h := range hosts {
		hc := &HostConfig{Host: h}
		for _, r := range routeMap[h.ID] {
			rule := RouteRule{
				Route:      r,
				PathPrefix: r.PathPrefix,
			}
			if r.ManagedComponentID != nil {
				rule.ManagedBackends = managedBackends[*r.ManagedComponentID]
			}
			hc.Routes = append(hc.Routes, rule)
		}
		// Resolve per-host JWT config: decrypt the stored ciphertext once
		// per reload so the hot path never pays AES cost. A failed decrypt
		// disables the override rather than killing the whole reload.
		hc.JWTIdentityEnabled = h.JWTIdentityEnabled
		hc.JWTIdentityMode = h.JWTIdentityMode
		if h.JWTClaims != "" {
			hc.JWTClaims = splitClaims(h.JWTClaims)
		}
		if h.JWTSecret != "" {
			hc.JWTSecret = decryptSetting(box, h.JWTSecret, "host:"+h.Domain+":jwt_secret")
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

	g.Correlation = loadCorrelationConfig(settings)

	return g, nil
}

func loadCorrelationConfig(settings map[string]json.RawMessage) CorrelationConfig {
	secs := func(key string, def int) time.Duration {
		return time.Duration(getIntSetting(settings, key, def)) * time.Second
	}

	c := CorrelationConfig{
		PathScanDistinct: getIntSetting(settings, "correlation_path_scan_distinct", 10),
		PathScanWindow:   secs("correlation_path_scan_window_seconds", 120),

		AuthBruteCount:  getIntSetting(settings, "correlation_auth_brute_count", 5),
		AuthBruteWindow: secs("correlation_auth_brute_window_seconds", 120),
		AuthPaths: splitCSV(getStrSetting(settings, "correlation_auth_paths",
			"/login,/api/auth/login,/api/auth/login/,/api/authentication/login,/api/authentication/login/")),

		WafRepeatCount:  getIntSetting(settings, "correlation_waf_repeat_count", 3),
		WafRepeatWindow: secs("correlation_waf_repeat_window_seconds", 300),

		ErrorSpikeCount:  getIntSetting(settings, "correlation_error_spike_count", 10),
		ErrorSpikeWindow: secs("correlation_error_spike_window_seconds", 60),

		AnomalyEnabled:     getBoolSetting(settings, "correlation_anomaly_enabled", true),
		AnomalyRatio:       getFloatSetting(settings, "correlation_anomaly_ratio", 3.0),
		AnomalyBaseline:    secs("correlation_anomaly_baseline_seconds", 600),
		AnomalyCurrent:     secs("correlation_anomaly_current_seconds", 60),
		AnomalyMinBaseline: getIntSetting(settings, "correlation_anomaly_min_baseline", 20),

		SensitivePaths:     splitCSV(getStrSetting(settings, "correlation_sensitive_paths", "")),
		SensitiveThreshold: getIntSetting(settings, "correlation_sensitive_threshold", 10),
		SensitiveWindow:    secs("correlation_sensitive_window_seconds", 300),

		ExportThreshold: getIntSetting(settings, "correlation_export_threshold", 5),
		ExportWindow:    secs("correlation_export_window_seconds", 300),
	}

	// Compile export pattern once per reload. Invalid regex disables the rule
	// rather than crashing the pipeline — the warning shows up in logs and
	// ops can fix it in the admin panel without a restart.
	if pat := getStrSetting(settings, "correlation_export_pattern",
		`(?i)(download|export|report|\.pdf|\.xlsx|\.csv)`); pat != "" {
		if re, err := regexp.Compile(pat); err != nil {
			slog.Warn("correlation: invalid export pattern, rule disabled", "pattern", pat, "error", err)
		} else {
			c.ExportPattern = re
		}
	}

	return c
}

// splitCSV trims whitespace and drops empty entries; empty strings → nil so
// callers can treat "no paths configured" as "rule disabled" by simple len().
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
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
