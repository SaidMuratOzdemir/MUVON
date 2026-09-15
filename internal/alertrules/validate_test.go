package alertrules

import (
	"strings"
	"testing"
)

func validRule() Rule {
	project := 1
	return Rule{
		Kind:      KindEvent,
		Name:      "Payment could not be captured",
		ProjectID: &project,
		Match: Match{Any: []MatchClause{
			{Events: []string{"PAYMENT_BLOCKED"}},
			{Events: []string{"JOB_FAILED"}, Fields: []FieldCondition{{Key: "job_family", Op: OpEquals, Values: []string{"payment"}}}},
		}},
		GroupBy: "job_id",
		Tiers: []Tier{
			{Severity: SeverityWarning, Trigger: Trigger{Type: TriggerEach}},
			{Severity: SeverityCritical, Trigger: Trigger{Type: TriggerCount, Count: 2, WindowSeconds: 7200}},
		},
		NotifyFields:  []string{"job_id"},
		Delivery:      DeliveryInstant,
		RemindMinutes: 240,
		ChannelIDs:    []string{"0192a000-0000-7000-8000-000000000001"},
	}
}

func TestValidateEventRuleAcceptsAWellFormedRule(t *testing.T) {
	if err := ValidateEventRule(validRule()); err != nil {
		t.Fatalf("ValidateEventRule: %v", err)
	}
	// A daily summary with an anomaly tier.
	r := validRule()
	r.GroupBy = ""
	r.Delivery = DeliveryDigest
	r.Tiers = []Tier{
		{Severity: SeverityInfo, Trigger: Trigger{Type: TriggerEach}},
		{Severity: SeverityWarning, Trigger: Trigger{Type: TriggerBaseline, Ratio: 3, BaselineDays: 7, Count: 1}},
	}
	if err := ValidateEventRule(r); err != nil {
		t.Fatalf("baseline rule: %v", err)
	}
}

func TestValidateEventRuleRejects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Rule)
		field  string
	}{
		{"no name", func(r *Rule) { r.Name = " " }, "name"},
		{"no project", func(r *Rule) { r.ProjectID = nil }, "project"},
		{"no clauses", func(r *Rule) { r.Match.Any = nil }, "match"},
		{"clause without events", func(r *Rule) { r.Match.Any[0].Events = nil }, "match.any[0].events"},
		{"event name with spaces", func(r *Rule) { r.Match.Any[0].Events = []string{"payment failed"} }, "match.any[0].events"},
		{"condition on event.name", func(r *Rule) {
			r.Match.Any[1].Fields[0].Key = EventNameField
		}, "match.any[1].fields[0].key"},
		{"eq with two values", func(r *Rule) { r.Match.Any[1].Fields[0].Values = []string{"a", "b"} }, "match.any[1].fields[0].values"},
		{"unknown operator", func(r *Rule) { r.Match.Any[1].Fields[0].Op = "regex" }, "match.any[1].fields[0].op"},
		{"no tiers", func(r *Rule) { r.Tiers = nil }, "tiers"},
		{"tiers out of order", func(r *Rule) { r.Tiers[0], r.Tiers[1] = r.Tiers[1], r.Tiers[0] }, "tiers[1].severity"},
		{"same severity twice", func(r *Rule) { r.Tiers[1].Severity = SeverityWarning }, "tiers[1].severity"},
		{"count of one", func(r *Rule) { r.Tiers[1].Trigger.Count = 1 }, "tiers[1].trigger.count"},
		{"window too short", func(r *Rule) { r.Tiers[1].Trigger.WindowSeconds = 10 }, "tiers[1].trigger.window_seconds"},
		{"window beyond retention", func(r *Rule) { r.Tiers[1].Trigger.WindowSeconds = 30 * 24 * 3600 }, "tiers[1].trigger.window_seconds"},
		{"each with parameters", func(r *Rule) { r.Tiers[0].Trigger.Count = 5 }, "tiers[0].trigger"},
		{"distinct without field", func(r *Rule) {
			r.Tiers[1].Trigger = Trigger{Type: TriggerDistinct, Count: 3, WindowSeconds: 900}
		}, "tiers[1].trigger.field"},
		{"baseline ratio of one", func(r *Rule) {
			r.Tiers[1].Trigger = Trigger{Type: TriggerBaseline, Ratio: 1, BaselineDays: 7, Count: 1}
		}, "tiers[1].trigger.ratio"},
		{"baseline beyond retention", func(r *Rule) {
			r.Tiers[1].Trigger = Trigger{Type: TriggerBaseline, Ratio: 3, BaselineDays: 30, Count: 1}
		}, "tiers[1].trigger.baseline_days"},
		{"group by event name", func(r *Rule) { r.GroupBy = EventNameField }, "group_by"},
		{"unknown delivery", func(r *Rule) { r.Delivery = "sms" }, "delivery"},
		{"reminder every minute", func(r *Rule) { r.RemindMinutes = 1 }, "remind_minutes"},
		{"channel id not a uuid", func(r *Rule) { r.ChannelIDs = []string{"ops"} }, "channel_ids"},
		{"duplicate channel", func(r *Rule) { r.ChannelIDs = append(r.ChannelIDs, r.ChannelIDs[0]) }, "channel_ids"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := validRule()
			tc.mutate(&r)
			err := ValidateEventRule(r)
			if err == nil {
				t.Fatal("accepted")
			}
			ve, ok := err.(*ValidationError)
			if !ok || ve.Field != tc.field {
				t.Fatalf("error = %v, want a validation error on %s", err, tc.field)
			}
		})
	}
}

func TestValidateChannel(t *testing.T) {
	slack := Channel{Name: "ops", Kind: ChannelSlack, SlackWebhook: "https://hooks.example.com/services/x", DigestTimezone: "Europe/Istanbul", DigestHour: 9}
	if err := ValidateChannel(slack, true); err != nil {
		t.Fatalf("slack: %v", err)
	}
	email := Channel{Name: "team", Kind: ChannelEmail, EmailTo: []string{"ops@example.com"}, DigestTimezone: "UTC"}
	if err := ValidateChannel(email, true); err != nil {
		t.Fatalf("email: %v", err)
	}

	for _, tc := range []struct {
		name string
		c    Channel
		want string
	}{
		{"plain http webhook", func() Channel { c := slack; c.SlackWebhook = "http://hooks.example.com/x"; return c }(), "slack_webhook"},
		{"missing webhook on create", func() Channel { c := slack; c.SlackWebhook = ""; return c }(), "slack_webhook"},
		{"recipient with a display name", func() Channel { c := email; c.EmailTo = []string{"Ops <ops@example.com>"}; return c }(), "email_to"},
		{"no recipients", func() Channel { c := email; c.EmailTo = nil; return c }(), "email_to"},
		{"unknown zone", func() Channel { c := email; c.DigestTimezone = "Mars/Olympus"; return c }(), "digest_timezone"},
		{"hour out of range", func() Channel { c := email; c.DigestHour = 24; return c }(), "digest_hour"},
		{"unknown kind", func() Channel { c := email; c.Kind = "sms"; return c }(), "kind"},
	} {
		err := ValidateChannel(tc.c, true)
		if err == nil || !strings.HasPrefix(err.Error(), tc.want+":") {
			t.Errorf("%s: error = %v, want one on %s", tc.name, err, tc.want)
		}
	}
	// Editing a Slack channel without retyping the webhook keeps the stored one.
	noWebhook := slack
	noWebhook.SlackWebhook = ""
	if err := ValidateChannel(noWebhook, false); err != nil {
		t.Fatalf("update without webhook: %v", err)
	}
}
