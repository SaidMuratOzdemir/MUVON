package alertrules

import (
	"sort"
	"strings"
)

// Event is a log line reduced to what rules read: the event name and the
// line's top-level fields.
type Event struct {
	Name   string
	Fields map[string]string
}

// EventFromAttrs reads an event from a JSON log line's parsed fields. A line
// without an event.name is not an event, whatever else it contains.
func EventFromAttrs(attrs map[string]string) (Event, bool) {
	name := strings.TrimSpace(attrs[EventNameField])
	if name == "" {
		return Event{}, false
	}
	return Event{Name: name, Fields: attrs}, true
}

// AppliesTo reports whether an event rule watches this project and component.
func (r Rule) AppliesTo(project, component string) bool {
	return r.Kind == KindEvent && r.Enabled && project != "" && r.ProjectSlug == project &&
		(r.Component == "" || r.Component == component)
}

// Matches reports whether any clause matches the event.
func (m Match) Matches(ev Event) bool {
	for _, c := range m.Any {
		if c.matches(ev) {
			return true
		}
	}
	return false
}

func (c MatchClause) matches(ev Event) bool {
	named := false
	for _, e := range c.Events {
		if e == ev.Name {
			named = true
			break
		}
	}
	if !named {
		return false
	}
	for _, f := range c.Fields {
		if !f.holds(ev.Fields) {
			return false
		}
	}
	return true
}

func (f FieldCondition) holds(fields map[string]string) bool {
	v, present := fields[f.Key]
	switch f.Op {
	case OpExists:
		return present
	case OpEquals:
		return present && len(f.Values) > 0 && v == f.Values[0]
	case OpNotEquals:
		// A missing field is not equal to the value, which is what someone
		// excluding one job family means.
		return !present || len(f.Values) == 0 || v != f.Values[0]
	case OpIn:
		return present && contains(f.Values, v)
	case OpNotIn:
		return !present || !contains(f.Values, v)
	}
	return false
}

func contains(values []string, v string) bool {
	for _, x := range values {
		if x == v {
			return true
		}
	}
	return false
}

// EventNames lists every event name the rule can match, for indexing.
func (m Match) EventNames() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range m.Any {
		for _, e := range c.Events {
			if !seen[e] {
				seen[e] = true
				out = append(out, e)
			}
		}
	}
	sort.Strings(out)
	return out
}

// GroupKey is the value that separates one incident of the rule from another,
// rendered as "field=value". A rule without group_by has a single incident.
func (r Rule) GroupKey(ev Event) string {
	if r.GroupBy == "" {
		return ""
	}
	return r.GroupBy + "=" + ev.Fields[r.GroupBy]
}

// ReferencedFields is every field the rule reads or reports: conditions,
// grouping, distinct counts and notification fields. A hit keeps exactly
// these, so evaluation never needs the full line and nothing else is copied.
func (r Rule) ReferencedFields() []string {
	seen := map[string]bool{EventNameField: true}
	out := []string{EventNameField}
	add := func(k string) {
		if k != "" && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for _, c := range r.Match.Any {
		for _, f := range c.Fields {
			add(f.Key)
		}
	}
	add(r.GroupBy)
	for _, t := range r.Tiers {
		if t.Trigger.Type == TriggerDistinct {
			add(t.Trigger.Field)
		}
	}
	for _, k := range r.NotifyFields {
		add(k)
	}
	return out
}

// PickFields copies the named fields that the event carries.
func PickFields(ev Event, keys []string) map[string]string {
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		if v, ok := ev.Fields[k]; ok {
			out[k] = v
		}
	}
	return out
}
