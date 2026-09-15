package alertrules

import (
	"reflect"
	"testing"
)

func ev(name string, fields map[string]string) Event {
	f := map[string]string{EventNameField: name}
	for k, v := range fields {
		f[k] = v
	}
	return Event{Name: name, Fields: f}
}

// One rule covering an event on its own and another only for one job family:
// the case clauses exist for.
func TestMatchClausesAreAlternatives(t *testing.T) {
	m := Match{Any: []MatchClause{
		{Events: []string{"PAYMENT_BLOCKED", "PAYMENT_RETRY_EXHAUSTED"}},
		{Events: []string{"JOB_FAILED"}, Fields: []FieldCondition{{Key: "job_family", Op: OpEquals, Values: []string{"payment"}}}},
	}}
	for _, tc := range []struct {
		name string
		ev   Event
		want bool
	}{
		{"first clause, no conditions", ev("PAYMENT_BLOCKED", nil), true},
		{"second clause, condition holds", ev("JOB_FAILED", map[string]string{"job_family": "payment"}), true},
		{"second clause, other family", ev("JOB_FAILED", map[string]string{"job_family": "email"}), false},
		{"second clause, field missing", ev("JOB_FAILED", nil), false},
		{"unrelated event", ev("USER_LOGIN", nil), false},
	} {
		if got := m.Matches(tc.ev); got != tc.want {
			t.Errorf("%s: Matches = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFieldConditionOperators(t *testing.T) {
	fields := map[string]string{"reason": "rejected", "attempts": "5"}
	for _, tc := range []struct {
		c    FieldCondition
		want bool
	}{
		{FieldCondition{Key: "reason", Op: OpEquals, Values: []string{"rejected"}}, true},
		{FieldCondition{Key: "reason", Op: OpEquals, Values: []string{"late"}}, false},
		{FieldCondition{Key: "reason", Op: OpNotEquals, Values: []string{"late"}}, true},
		{FieldCondition{Key: "missing", Op: OpNotEquals, Values: []string{"x"}}, true},
		{FieldCondition{Key: "reason", Op: OpIn, Values: []string{"rejected", "unembeddable"}}, true},
		{FieldCondition{Key: "missing", Op: OpIn, Values: []string{"x"}}, false},
		{FieldCondition{Key: "reason", Op: OpNotIn, Values: []string{"rejected"}}, false},
		{FieldCondition{Key: "missing", Op: OpNotIn, Values: []string{"x"}}, true},
		{FieldCondition{Key: "attempts", Op: OpExists}, true},
		{FieldCondition{Key: "missing", Op: OpExists}, false},
		{FieldCondition{Key: "reason", Op: "regex", Values: []string{".*"}}, false},
	} {
		if got := tc.c.holds(fields); got != tc.want {
			t.Errorf("%+v holds = %v, want %v", tc.c, got, tc.want)
		}
	}
}

func TestEventFromAttrsRequiresEventName(t *testing.T) {
	if _, ok := EventFromAttrs(map[string]string{"level": "error", "msg": "boom"}); ok {
		t.Error("a JSON line without event.name was treated as an event")
	}
	got, ok := EventFromAttrs(map[string]string{EventNameField: " JOB_STUCK "})
	if !ok || got.Name != "JOB_STUCK" {
		t.Errorf("EventFromAttrs = %+v, %v", got, ok)
	}
}

func TestRuleAppliesTo(t *testing.T) {
	r := Rule{Kind: KindEvent, Enabled: true, ProjectSlug: "shop"}
	if !r.AppliesTo("shop", "worker") {
		t.Error("a rule without a component must cover every component")
	}
	r.Component = "worker"
	if r.AppliesTo("shop", "api") || !r.AppliesTo("shop", "worker") {
		t.Error("component scoping is wrong")
	}
	if r.AppliesTo("", "worker") {
		t.Error("a line with no verified project must not match")
	}
	r.Enabled = false
	if r.AppliesTo("shop", "worker") {
		t.Error("a disabled rule applied")
	}
}

func TestGroupKeyAndReferencedFields(t *testing.T) {
	r := Rule{
		Match: Match{Any: []MatchClause{{Events: []string{"JOB_STUCK"},
			Fields: []FieldCondition{{Key: "job_family", Op: OpEquals, Values: []string{"payment"}}}}}},
		GroupBy:      "job_id",
		Tiers:        []Tier{{Severity: SeverityCritical, Trigger: Trigger{Type: TriggerDistinct, Field: "worker", Count: 3, WindowSeconds: 900}}},
		NotifyFields: []string{"attempts", "job_id"},
	}
	if got := r.GroupKey(ev("JOB_STUCK", map[string]string{"job_id": "42"})); got != "job_id=42" {
		t.Errorf("GroupKey = %q", got)
	}
	want := []string{EventNameField, "job_family", "job_id", "worker", "attempts"}
	if got := r.ReferencedFields(); !reflect.DeepEqual(got, want) {
		t.Errorf("ReferencedFields = %v, want %v", got, want)
	}
	if got := (Rule{}).GroupKey(ev("X", nil)); got != "" {
		t.Errorf("ungrouped rule GroupKey = %q, want empty", got)
	}
}
