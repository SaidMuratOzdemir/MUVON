// Package alertrules holds the alert rule and channel model shared by the
// admin API, which edits it, and dialog-siem, which evaluates it. It has no
// dependency on the database or on transport so both sides agree on one
// definition of what a valid rule is.
package alertrules

import "time"

// Severities, lowest first.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// SeverityRank orders severities so an escalation can be recognised. An
// unknown value ranks below info.
func SeverityRank(s string) int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityWarning:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	}
	return 0
}

// ValidSeverity reports whether s is one of the four severities.
func ValidSeverity(s string) bool { return SeverityRank(s) > 0 }

// Delivery modes.
const (
	// DeliveryInstant notifies when an alert opens or escalates.
	DeliveryInstant = "instant"
	// DeliveryDigest collects alerts into the channel's daily summary.
	DeliveryDigest = "digest"
	// DeliveryNone records alerts on the Alerts page only.
	DeliveryNone = "none"
)

// ValidDelivery reports whether d is a known delivery mode.
func ValidDelivery(d string) bool {
	return d == DeliveryInstant || d == DeliveryDigest || d == DeliveryNone
}

// Rule kinds.
const (
	// KindBuiltin is a detection shipped in code, such as the HTTP
	// correlation rules. Its logic is fixed; routing is the operator's.
	KindBuiltin = "builtin"
	// KindEvent matches events applications write to their logs.
	KindEvent = "event"
)

// Channel kinds.
const (
	ChannelSlack = "slack"
	ChannelEmail = "email"
)

// Channel is a named notification destination.
type Channel struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
	// SlackWebhook is ciphertext at rest and plaintext only inside
	// dialog-siem's snapshot. It never leaves the server.
	SlackWebhook   string    `json:"-"`
	EmailTo        []string  `json:"email_to"`
	DigestHour     int       `json:"digest_hour"`
	DigestTimezone string    `json:"digest_timezone"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Rule is either a builtin detection or an application event rule.
type Rule struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	BuiltinKey  string `json:"builtin_key,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`

	// Event rules only. ProjectSlug is resolved from ProjectID on read.
	ProjectID    *int     `json:"project_id,omitempty"`
	ProjectSlug  string   `json:"project,omitempty"`
	Component    string   `json:"component"`
	Match        Match    `json:"match"`
	GroupBy      string   `json:"group_by"`
	Tiers        []Tier   `json:"tiers"`
	NotifyFields []string `json:"notify_fields"`

	Delivery      string   `json:"delivery"`
	RemindMinutes int      `json:"remind_minutes"`
	ChannelIDs    []string `json:"channel_ids"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Match selects the log lines a rule looks at: a line matches when any clause
// does. Clauses let one rule cover events that need different conditions,
// such as one event on its own and another only for a particular job family.
type Match struct {
	Any []MatchClause `json:"any"`
}

// MatchClause matches a line whose event.name is one of Events and whose
// fields satisfy every condition.
type MatchClause struct {
	Events []string         `json:"events"`
	Fields []FieldCondition `json:"fields"`
}

// Field condition operators.
const (
	OpEquals    = "eq"
	OpNotEquals = "ne"
	OpIn        = "in"
	OpNotIn     = "not_in"
	OpExists    = "exists"
)

// FieldCondition narrows a match on one top-level field of the event.
type FieldCondition struct {
	Key    string   `json:"key"`
	Op     string   `json:"op"`
	Values []string `json:"values"`
}

// Tier is one severity a rule can reach and what it takes to reach it. A rule
// reports the highest tier whose trigger holds.
type Tier struct {
	Severity string  `json:"severity"`
	Trigger  Trigger `json:"trigger"`
}

// Trigger types.
const (
	// TriggerEach fires on every matching event.
	TriggerEach = "each"
	// TriggerCount fires when Count events arrive within WindowSeconds.
	TriggerCount = "count"
	// TriggerDistinct fires when Count different values of Field arrive
	// within WindowSeconds.
	TriggerDistinct = "distinct"
	// TriggerBaseline fires when the last 24 hours hold at least Count
	// events and more than Ratio times the daily average of the
	// BaselineDays before them.
	TriggerBaseline = "baseline"
)

// Trigger is the condition of one tier.
type Trigger struct {
	Type          string  `json:"type"`
	Count         int     `json:"count,omitempty"`
	WindowSeconds int     `json:"window_seconds,omitempty"`
	Field         string  `json:"field,omitempty"`
	Ratio         float64 `json:"ratio,omitempty"`
	BaselineDays  int     `json:"baseline_days,omitempty"`
}

// EventNameField is the log field that names an application event.
const EventNameField = "event.name"
