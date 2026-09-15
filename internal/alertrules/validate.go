package alertrules

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits. They keep a rule cheap to evaluate on every batch and an alert
// readable; none is meant to be reached by a sensible rule.
const (
	maxNameLength       = 120
	maxDescription      = 1000
	maxClauses          = 10
	maxEventsPerClause  = 20
	maxFieldConditions  = 10
	maxConditionValues  = 50
	maxValueLength      = 256
	maxTiers            = 4
	maxNotifyFields     = 10
	maxChannelsPerRule  = 20
	maxCount            = 100000
	minWindowSeconds    = 60
	maxWindowSeconds    = 7 * 24 * 3600
	maxBaselineDays     = 7
	maxBaselineRatio    = 100
	minRemindMinutes    = 15
	maxRemindMinutes    = 7 * 24 * 60
	maxEmailRecipients  = 20
	maxChannelNameLen   = 80
	maxComponentNameLen = 64
)

// HitRetention is how long matched events are kept for windows and
// baselines: the longest of either, plus a day of margin.
const HitRetention = (maxBaselineDays + 1) * 24 * time.Hour

var (
	eventNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	fieldKeyPattern  = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,64}$`)
	uuidPattern      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// ValidationError names the part of a rule or channel that is wrong.
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string { return e.Field + ": " + e.Reason }

func invalid(field, format string, args ...any) error {
	return &ValidationError{Field: field, Reason: fmt.Sprintf(format, args...)}
}

// ValidateEventRule checks an event rule before it is stored. ProjectID must
// already be resolved; whether the project and channels exist is the
// caller's to check.
func ValidateEventRule(r Rule) error {
	if r.Kind != KindEvent {
		return invalid("kind", "must be %q", KindEvent)
	}
	if err := validateName(r.Name); err != nil {
		return err
	}
	if utf8.RuneCountInString(r.Description) > maxDescription {
		return invalid("description", "longer than %d characters", maxDescription)
	}
	if r.ProjectID == nil {
		return invalid("project", "is required")
	}
	if len(r.Component) > maxComponentNameLen || strings.TrimSpace(r.Component) != r.Component {
		return invalid("component", "is not a valid component slug")
	}
	if err := validateMatch(r.Match); err != nil {
		return err
	}
	if r.GroupBy != "" && !fieldKeyPattern.MatchString(r.GroupBy) {
		return invalid("group_by", "is not a valid field name")
	}
	if r.GroupBy == EventNameField {
		return invalid("group_by", "cannot be %s; every incident would be a single event name", EventNameField)
	}
	if err := validateTiers(r.Tiers); err != nil {
		return err
	}
	if len(r.NotifyFields) > maxNotifyFields {
		return invalid("notify_fields", "at most %d fields", maxNotifyFields)
	}
	for _, k := range r.NotifyFields {
		if !fieldKeyPattern.MatchString(k) {
			return invalid("notify_fields", "%q is not a valid field name", k)
		}
	}
	return ValidateRouting(r.Delivery, r.RemindMinutes, r.ChannelIDs)
}

// ValidateRouting checks what the operator may change on any rule, builtin
// ones included.
func ValidateRouting(delivery string, remindMinutes int, channelIDs []string) error {
	if !ValidDelivery(delivery) {
		return invalid("delivery", "must be instant, digest or none")
	}
	if remindMinutes != 0 && (remindMinutes < minRemindMinutes || remindMinutes > maxRemindMinutes) {
		return invalid("remind_minutes", "must be 0 or between %d and %d", minRemindMinutes, maxRemindMinutes)
	}
	if len(channelIDs) > maxChannelsPerRule {
		return invalid("channel_ids", "at most %d channels", maxChannelsPerRule)
	}
	seen := map[string]bool{}
	for _, id := range channelIDs {
		if !uuidPattern.MatchString(id) {
			return invalid("channel_ids", "%q is not a channel id", id)
		}
		if seen[id] {
			return invalid("channel_ids", "%q is listed twice", id)
		}
		seen[id] = true
	}
	return nil
}

func validateName(name string) error {
	if strings.TrimSpace(name) == "" {
		return invalid("name", "is required")
	}
	if utf8.RuneCountInString(name) > maxNameLength {
		return invalid("name", "longer than %d characters", maxNameLength)
	}
	return nil
}

func validateMatch(m Match) error {
	if len(m.Any) == 0 {
		return invalid("match", "needs at least one clause")
	}
	if len(m.Any) > maxClauses {
		return invalid("match", "at most %d clauses", maxClauses)
	}
	for i, c := range m.Any {
		field := fmt.Sprintf("match.any[%d]", i)
		if len(c.Events) == 0 {
			return invalid(field+".events", "needs at least one event name")
		}
		if len(c.Events) > maxEventsPerClause {
			return invalid(field+".events", "at most %d event names", maxEventsPerClause)
		}
		for _, e := range c.Events {
			if !eventNamePattern.MatchString(e) {
				return invalid(field+".events", "%q is not a valid event name", e)
			}
		}
		if len(c.Fields) > maxFieldConditions {
			return invalid(field+".fields", "at most %d conditions", maxFieldConditions)
		}
		for j, f := range c.Fields {
			if err := validateCondition(fmt.Sprintf("%s.fields[%d]", field, j), f); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateCondition(field string, f FieldCondition) error {
	if !fieldKeyPattern.MatchString(f.Key) {
		return invalid(field+".key", "is not a valid field name")
	}
	if f.Key == EventNameField {
		return invalid(field+".key", "event names belong in events, not in a condition")
	}
	switch f.Op {
	case OpExists:
		if len(f.Values) != 0 {
			return invalid(field+".values", "exists takes no values")
		}
	case OpEquals, OpNotEquals:
		if len(f.Values) != 1 {
			return invalid(field+".values", "%s takes exactly one value", f.Op)
		}
	case OpIn, OpNotIn:
		if len(f.Values) == 0 || len(f.Values) > maxConditionValues {
			return invalid(field+".values", "%s takes between 1 and %d values", f.Op, maxConditionValues)
		}
	default:
		return invalid(field+".op", "must be eq, ne, in, not_in or exists")
	}
	for _, v := range f.Values {
		if len(v) > maxValueLength {
			return invalid(field+".values", "a value is longer than %d bytes", maxValueLength)
		}
	}
	return nil
}

func validateTiers(tiers []Tier) error {
	if len(tiers) == 0 {
		return invalid("tiers", "needs at least one tier")
	}
	if len(tiers) > maxTiers {
		return invalid("tiers", "at most %d tiers", maxTiers)
	}
	prev := 0
	for i, t := range tiers {
		field := fmt.Sprintf("tiers[%d]", i)
		rank := SeverityRank(t.Severity)
		if rank == 0 {
			return invalid(field+".severity", "must be info, warning, high or critical")
		}
		// Ascending order makes "the highest tier that holds" unambiguous
		// and matches how the panel lists them.
		if rank <= prev {
			return invalid(field+".severity", "tiers must be listed from lowest to highest severity, each once")
		}
		prev = rank
		if err := validateTrigger(field+".trigger", t.Trigger); err != nil {
			return err
		}
	}
	return nil
}

func validateTrigger(field string, tr Trigger) error {
	window := func() error {
		if tr.WindowSeconds < minWindowSeconds || tr.WindowSeconds > maxWindowSeconds {
			return invalid(field+".window_seconds", "must be between %d and %d", minWindowSeconds, maxWindowSeconds)
		}
		return nil
	}
	switch tr.Type {
	case TriggerEach:
		if tr.Count != 0 || tr.WindowSeconds != 0 || tr.Field != "" || tr.Ratio != 0 || tr.BaselineDays != 0 {
			return invalid(field, "each takes no parameters")
		}
	case TriggerCount:
		if tr.Count < 2 || tr.Count > maxCount {
			return invalid(field+".count", "must be between 2 and %d; one event is the each trigger", maxCount)
		}
		if tr.Field != "" || tr.Ratio != 0 || tr.BaselineDays != 0 {
			return invalid(field, "count takes count and window_seconds only")
		}
		return window()
	case TriggerDistinct:
		if !fieldKeyPattern.MatchString(tr.Field) || tr.Field == EventNameField {
			return invalid(field+".field", "is not a valid field name")
		}
		if tr.Count < 2 || tr.Count > maxCount {
			return invalid(field+".count", "must be between 2 and %d", maxCount)
		}
		if tr.Ratio != 0 || tr.BaselineDays != 0 {
			return invalid(field, "distinct takes field, count and window_seconds only")
		}
		return window()
	case TriggerBaseline:
		if tr.Ratio <= 1 || tr.Ratio > maxBaselineRatio {
			return invalid(field+".ratio", "must be above 1 and at most %d", maxBaselineRatio)
		}
		if tr.BaselineDays < 1 || tr.BaselineDays > maxBaselineDays {
			return invalid(field+".baseline_days", "must be between 1 and %d", maxBaselineDays)
		}
		if tr.Count < 1 || tr.Count > maxCount {
			return invalid(field+".count", "is the minimum number of events in the last 24 hours, between 1 and %d", maxCount)
		}
		if tr.WindowSeconds != 0 || tr.Field != "" {
			return invalid(field, "baseline takes ratio, baseline_days and count only")
		}
	default:
		return invalid(field+".type", "must be each, count, distinct or baseline")
	}
	return nil
}

// ValidateChannel checks a channel before it is stored. For Slack the webhook
// is the plaintext the operator entered.
func ValidateChannel(c Channel, requireWebhook bool) error {
	name := strings.TrimSpace(c.Name)
	if name == "" {
		return invalid("name", "is required")
	}
	if utf8.RuneCountInString(name) > maxChannelNameLen {
		return invalid("name", "longer than %d characters", maxChannelNameLen)
	}
	switch c.Kind {
	case ChannelSlack:
		if len(c.EmailTo) != 0 {
			return invalid("email_to", "a Slack channel has no recipients")
		}
		if c.SlackWebhook == "" {
			if requireWebhook {
				return invalid("slack_webhook", "is required")
			}
			break
		}
		u, err := url.Parse(c.SlackWebhook)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return invalid("slack_webhook", "must be an https URL")
		}
	case ChannelEmail:
		if c.SlackWebhook != "" {
			return invalid("slack_webhook", "an email channel has no webhook")
		}
		if len(c.EmailTo) == 0 || len(c.EmailTo) > maxEmailRecipients {
			return invalid("email_to", "needs between 1 and %d recipients", maxEmailRecipients)
		}
		for _, r := range c.EmailTo {
			addr, err := mail.ParseAddress(r)
			if err != nil || addr.Address != r {
				return invalid("email_to", "%q is not a plain email address", r)
			}
		}
	default:
		return invalid("kind", "must be slack or email")
	}
	if c.DigestHour < 0 || c.DigestHour > 23 {
		return invalid("digest_hour", "must be between 0 and 23")
	}
	if _, err := time.LoadLocation(c.DigestTimezone); err != nil || c.DigestTimezone == "" {
		return invalid("digest_timezone", "is not a known time zone")
	}
	return nil
}

// IsValidationError reports whether err describes bad input rather than a
// failure to process it.
func IsValidationError(err error) bool {
	var v *ValidationError
	return errors.As(err, &v)
}
