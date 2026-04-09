package waf

import (
	"net/http"
	"time"
)

// Category represents an attack category detected by WAF rules.
type Category string

const (
	CatXSS                Category = "xss"
	CatSQLi               Category = "sqli"
	CatRCE                Category = "rce"
	CatLFI                Category = "lfi"
	CatRFI                Category = "rfi"
	CatSSRF               Category = "ssrf"
	CatNoSQLi             Category = "nosqli"
	CatSSTI               Category = "ssti"
	CatLog4Shell          Category = "log4shell"
	CatPrototypePollution Category = "prototype_pollution"
	CatSessionFixation    Category = "session_fixation"
	CatPathTraversal      Category = "path_traversal"
	CatCommandInjection   Category = "command_injection"
	CatCustom             Category = "custom"
)

// Action is the graduated WAF response based on cumulative IP score.
type Action string

const (
	ActionAllow     Action = "allow"
	ActionLog       Action = "log"
	ActionRateLimit Action = "rate_limit"
	ActionBlock     Action = "block"
	ActionTempBan   Action = "temp_ban"
	ActionBan       Action = "ban"
)

// ActionSeverityOrder defines the ordering of actions from least to most severe.
func ActionSeverityOrder(a Action) int {
	switch a {
	case ActionAllow:
		return 0
	case ActionLog:
		return 1
	case ActionRateLimit:
		return 2
	case ActionBlock:
		return 3
	case ActionTempBan:
		return 4
	case ActionBan:
		return 5
	default:
		return 0
	}
}

// Location identifies where a match was found in the request.
type Location string

const (
	LocPath   Location = "path"
	LocQuery  Location = "query"
	LocHeader Location = "header"
	LocBody   Location = "body"
)

// Rule is a WAF detection rule loaded from the database.
type Rule struct {
	ID          int
	Pattern     string
	IsRegex     bool
	Category    Category
	Severity    int // 1-100, contributes to request score
	Description string
	IsActive    bool
}

// RuleMatch records a single match during inspection.
type RuleMatch struct {
	RuleID   int      `json:"rule_id"`
	Category Category `json:"category"`
	Severity int      `json:"severity"`
	Location Location `json:"location"`
	Field    string   `json:"field"`   // e.g. "User-Agent", "q", "body"
	Snippet  string   `json:"snippet"` // first 200 chars around match
}

// InspectRequest bundles all data needed for WAF inspection.
type InspectRequest struct {
	RequestID     string
	ClientIP      string
	Host          string
	Method        string
	Path          string
	RawQuery      string
	Headers       http.Header
	Body          []byte
	ContentType   string
	RouteID       int
	DetectionOnly bool
}

// InspectResult is the outcome of WAF inspection.
type InspectResult struct {
	Action        Action      `json:"action"`
	RequestScore  int         `json:"request_score"`
	IPScore       float64     `json:"ip_score"`
	Matches       []RuleMatch `json:"matches,omitempty"`
	BlockReason   string      `json:"block_reason,omitempty"`
	DetectionOnly bool        `json:"detection_only"`
	ProcessingUs  int64       `json:"-"` // microseconds
}

// IPState tracks in-memory state for one IP address.
type IPState struct {
	Status          Action
	CumulativeScore float64
	LastSeen        time.Time
	BanUntil        time.Time
	BanReason       string
	Whitelisted     bool
	Hits            []ScoredHit
	Dirty           bool // needs persistence to DB
}

// ScoredHit is one data point in the scoring sliding window.
type ScoredHit struct {
	Score     int
	Timestamp time.Time
}

// WafEvent is logged asynchronously to waf_events table.
type WafEvent struct {
	Timestamp     time.Time
	RequestID     string
	ClientIP      string
	Host          string
	Method        string
	Path          string
	RequestScore  int
	IPScore       float64
	Action        Action
	MatchedRules  []RuleMatch
	DetectionMode bool
}

// Exclusion defines a per-route rule exclusion.
type Exclusion struct {
	ID        int
	RouteID   int
	RuleID    int
	Parameter string   // specific parameter name, empty = all
	Location  Location // path/query/header/body/all
}

// WafConfig holds all WAF-specific configuration loaded from settings.
type WafConfig struct {
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

// DefaultWafConfig returns sensible defaults.
func DefaultWafConfig() WafConfig {
	return WafConfig{
		EnabledGlobal:          true,
		DetectionOnly:          false,
		ThresholdLog:           0,
		ThresholdRateLimit:     11,
		ThresholdBlock:         26,
		ThresholdTempBan:       51,
		ThresholdBan:           101,
		IPScoreDecayPerHour:    5.0,
		IPScoreWindowHours:     24,
		TempBanDurationMinutes: 60,
		PatternCacheTTLSeconds: 60,
		VTTimeoutSeconds:       8,
		VTCacheTTLHours:        24,
		VTScoreContribution:    30,
		MaxBodyInspectBytes:    65536,
		NormalizationMaxIter:   3,
	}
}

// ContentPart represents a piece of the request to be inspected.
type ContentPart struct {
	Content  string
	Location Location
	Field    string // e.g. header name, parameter name, "body"
}
