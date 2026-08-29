// Package blocklist scores inbound requests against operator-managed path
// patterns and blocks the clients that cross a threshold.
//
// This is deliberately NOT a WAF: there is no body inspection and no rule
// language. The whole decision surface is (path, client address, time).
//
// It also cannot live in internal/correlation: that engine runs inside
// dialog-siem, after the log row has been written, which is far too late to
// refuse a request. Scoring happens in the proxy's own hot path instead.
//
// The pattern table is data, not code. It lives in the database, ships with a
// seeded default set and is edited from the panel, so adding a pattern never
// requires a release. This file holds only the matcher.
package blocklist

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Match kinds. Scanners nest their probes (/var/www/.git/config,
// /blog/blog/wp-json/batch/v1), so matching on the whole path is not enough:
// the same probe has to be recognised wherever it was rooted.
const (
	// KindFilename matches the last path segment, so /.env, /public/.env and
	// /old/backup/.env all reduce to one pattern.
	KindFilename = "filename"
	// KindSegment matches a run of consecutive segments anywhere in the path.
	KindSegment = "segment"
	// KindRegex matches the last segment against a regular expression, for
	// families that have no fixed name (numbered or random webshell drops).
	KindRegex = "regex"
	// KindAllow exempts a path prefix from scoring entirely. Checked first.
	KindAllow = "allow"
)

// Rule names group patterns for the operator and land on the block row.
const (
	RuleSecret  = "secret_file"
	RuleExploit = "exploit_probe"
	RuleAdmin   = "admin_probe"
	RuleLeak    = "artifact_probe"
)

// Suggested weights for the seeded set. A single secret-file hit clears the
// default threshold on its own because a request for a credential file has no
// benign explanation; the lower tiers need company before they mean anything.
const (
	ScoreSecret  = 100
	ScoreExploit = 20
	ScoreAdmin   = 10
	ScoreLeak    = 5
)

// Pattern is one row of the operator-managed table.
type Pattern struct {
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
	Score   int    `json:"score"`
	Rule    string `json:"rule"`
	Enabled bool   `json:"enabled"`
	Builtin bool   `json:"builtin"`
	Note    string `json:"note,omitempty"`
}

// Match is the outcome of scoring one path.
type Match struct {
	Score   int
	Rule    string
	Pattern string // the entry that matched, for the operator's audit trail
}

// Set is a compiled pattern table, ready for the hot path. Build it once per
// config reload with Compile and treat it as immutable afterwards.
type Set struct {
	allow     []string
	filenames map[string]Pattern
	segments  []Pattern
	regexes   []compiledRegex
}

type compiledRegex struct {
	re  *regexp.Regexp
	pat Pattern
}

// Compile turns operator rows into a matcher. Disabled rows are skipped.
//
// A bad regex disables that one row and is reported, rather than failing the
// whole set: one typo in the panel must not switch the product's defences off.
func Compile(rows []Pattern) (*Set, []error) {
	s := &Set{filenames: make(map[string]Pattern, len(rows))}
	var errs []error

	for _, p := range rows {
		if !p.Enabled || p.Pattern == "" {
			continue
		}
		p.Pattern = strings.ToLower(strings.TrimSpace(p.Pattern))

		switch p.Kind {
		case KindAllow:
			s.allow = append(s.allow, p.Pattern)
		case KindFilename:
			s.filenames[p.Pattern] = p
		case KindSegment:
			s.segments = append(s.segments, p)
		case KindRegex:
			re, err := regexp.Compile(p.Pattern)
			if err != nil {
				errs = append(errs, fmt.Errorf("blocklist pattern %q: %w", p.Pattern, err))
				continue
			}
			s.regexes = append(s.regexes, compiledRegex{re: re, pat: p})
		default:
			errs = append(errs, fmt.Errorf("blocklist pattern %q: unknown kind %q", p.Pattern, p.Kind))
		}
	}

	// Highest score first so the first segment hit is also the worst one and
	// scoring can stop there.
	sort.Slice(s.segments, func(i, j int) bool { return s.segments[i].Score > s.segments[j].Score })
	return s, errs
}

// Empty reports whether the set would never match anything. The proxy uses this
// to skip work entirely when no patterns are configured.
func (s *Set) Empty() bool {
	if s == nil {
		return true
	}
	return len(s.filenames) == 0 && len(s.segments) == 0 && len(s.regexes) == 0
}

// Score evaluates one request path. A zero Score means nothing matched and the
// caller should not touch the client's record at all.
//
// Matching is case-insensitive and runs on the cleaned path, because scanners
// rotate case and inject //double//slashes to dodge exact comparisons. Both
// shapes were present in observed traffic.
func (s *Set) Score(rawPath string) Match {
	if s == nil {
		return Match{}
	}
	p := normalise(rawPath)
	if p == "" {
		return Match{}
	}

	for _, a := range s.allow {
		if strings.HasPrefix(p, a) {
			return Match{}
		}
	}

	// Filename first: cheapest lookup, most specific signal.
	name := lastSegment(p)
	if name != "" {
		if hit, ok := s.filenames[name]; ok {
			return Match{Score: hit.Score, Rule: hit.Rule, Pattern: hit.Pattern}
		}
		for _, r := range s.regexes {
			if r.re.MatchString(name) {
				return Match{Score: r.pat.Score, Rule: r.pat.Rule, Pattern: r.pat.Pattern}
			}
		}
	}

	// Then segment runs. Sorted by score, so the first hit is the worst one.
	for _, seg := range s.segments {
		if strings.Contains(p, seg.Pattern) {
			return Match{Score: seg.Score, Rule: seg.Rule, Pattern: seg.Pattern}
		}
	}
	return Match{}
}

// normalise lowercases the path, strips the query, collapses repeated slashes
// and guarantees a leading slash.
func normalise(p string) string {
	if p == "" {
		return ""
	}
	p = strings.ToLower(p)
	if i := strings.IndexAny(p, "?#"); i != -1 {
		p = p[:i]
	}
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// lastSegment returns the filename portion, ignoring a trailing slash so that
// /config.php/ reads the same as /config.php.
func lastSegment(p string) string {
	p = strings.TrimSuffix(p, "/")
	if i := strings.LastIndex(p, "/"); i != -1 {
		return p[i+1:]
	}
	return p
}
