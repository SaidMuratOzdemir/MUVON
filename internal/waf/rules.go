package waf

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"muvon/internal/db"
)

// CompiledRegex holds a pre-compiled regex pattern alongside its rule metadata.
type CompiledRegex struct {
	Rule  Rule
	Regex *regexp.Regexp
}

// RuleCache holds compiled pattern matching structures and refreshes them from the database.
type RuleCache struct {
	mu          sync.RWMutex
	acAutomaton *AhoCorasick
	acRules     []Rule // rules corresponding to AC pattern indices
	regexRules  []CompiledRegex
	exclusions  map[int][]Exclusion // routeID -> exclusions
	lastRefresh time.Time
	ttl         time.Duration
	database    *db.DB
}

// NewRuleCache creates a new cache with the given TTL.
func NewRuleCache(database *db.DB, ttlSeconds int) *RuleCache {
	if ttlSeconds <= 0 {
		ttlSeconds = 60
	}
	return &RuleCache{
		database:   database,
		ttl:        time.Duration(ttlSeconds) * time.Second,
		exclusions: make(map[int][]Exclusion),
	}
}

// Refresh reloads rules from PostgreSQL, rebuilds the Aho-Corasick automaton,
// and compiles all regex patterns. Safe for concurrent use.
func (rc *RuleCache) Refresh(ctx context.Context) error {
	// Load rules from DB
	dbRules, err := rc.database.ListActiveWafRules(ctx)
	if err != nil {
		return fmt.Errorf("rule cache refresh: %w", err)
	}

	// Load exclusions
	dbExcl, err := rc.database.ListWafExclusions(ctx)
	if err != nil {
		return fmt.Errorf("rule cache refresh exclusions: %w", err)
	}

	// Separate substring and regex rules
	var substringPatterns []string
	var substringRules []Rule
	var regexRules []CompiledRegex

	for _, dr := range dbRules {
		rule := Rule{
			ID:          dr.ID,
			Pattern:     dr.Pattern,
			IsRegex:     dr.IsRegex,
			Category:    Category(dr.Category),
			Severity:    dr.Severity,
			Description: dr.Description,
			IsActive:    dr.IsActive,
		}

		if dr.IsRegex {
			compiled, err := compileRegex(dr.Pattern)
			if err != nil {
				slog.Warn("skipping invalid regex pattern",
					"rule_id", dr.ID, "pattern", dr.Pattern, "error", err)
				continue
			}
			regexRules = append(regexRules, CompiledRegex{Rule: rule, Regex: compiled})
		} else {
			substringPatterns = append(substringPatterns, strings.ToLower(dr.Pattern))
			substringRules = append(substringRules, rule)
		}
	}

	// Build Aho-Corasick automaton
	var ac *AhoCorasick
	if len(substringPatterns) > 0 {
		ac = BuildAhoCorasick(substringPatterns)
	}

	// Build exclusion map
	exclMap := make(map[int][]Exclusion, len(dbExcl))
	for _, de := range dbExcl {
		excl := Exclusion{
			ID:        de.ID,
			RouteID:   de.RouteID,
			RuleID:    de.RuleID,
			Parameter: de.Parameter,
			Location:  Location(de.Location),
		}
		exclMap[de.RouteID] = append(exclMap[de.RouteID], excl)
	}

	// Swap in under write lock
	rc.mu.Lock()
	rc.acAutomaton = ac
	rc.acRules = substringRules
	rc.regexRules = regexRules
	rc.exclusions = exclMap
	rc.lastRefresh = time.Now()
	rc.mu.Unlock()

	slog.Info("waf rule cache refreshed",
		"substring_rules", len(substringRules),
		"regex_rules", len(regexRules),
		"exclusions", len(dbExcl))

	return nil
}

// EnsureFresh refreshes the cache if it has expired.
func (rc *RuleCache) EnsureFresh(ctx context.Context) {
	rc.mu.RLock()
	stale := time.Since(rc.lastRefresh) > rc.ttl
	rc.mu.RUnlock()

	if stale {
		if err := rc.Refresh(ctx); err != nil {
			slog.Error("waf rule cache refresh failed", "error", err)
		}
	}
}

// Match runs both AC and regex matching against all content variations for a given location.
// It filters out excluded rules for the given routeID/location/parameter.
func (rc *RuleCache) Match(variations []string, location Location, field string, routeID int) []RuleMatch {
	rc.mu.RLock()
	ac := rc.acAutomaton
	acRules := rc.acRules
	regexRules := rc.regexRules
	exclusions := rc.exclusions[routeID]
	rc.mu.RUnlock()

	var matches []RuleMatch

	// Phase 1: Aho-Corasick substring matching
	if ac != nil {
		for _, content := range variations {
			acMatches := ac.Search(content)
			for _, m := range acMatches {
				rule := acRules[m.PatternIndex]
				if isExcluded(rule.ID, location, field, exclusions) {
					continue
				}
				matches = append(matches, RuleMatch{
					RuleID:   rule.ID,
					Category: rule.Category,
					Severity: rule.Severity,
					Location: location,
					Field:    field,
					Snippet:  extractSnippet(content, m.Position, len(rule.Pattern)),
				})
			}
		}
	}

	// Phase 2: Regex matching
	for _, cr := range regexRules {
		if isExcluded(cr.Rule.ID, location, field, exclusions) {
			continue
		}
		for _, content := range variations {
			if loc := cr.Regex.FindStringIndex(content); loc != nil {
				matches = append(matches, RuleMatch{
					RuleID:   cr.Rule.ID,
					Category: cr.Rule.Category,
					Severity: cr.Rule.Severity,
					Location: location,
					Field:    field,
					Snippet:  extractSnippet(content, loc[1]-1, loc[1]-loc[0]),
				})
				break // one match per regex rule is enough
			}
		}
	}

	return matches
}

// RuleCount returns total loaded rules.
func (rc *RuleCache) RuleCount() int {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return len(rc.acRules) + len(rc.regexRules)
}

// compileRegex compiles a pattern with safety checks.
func compileRegex(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > 500 {
		return nil, fmt.Errorf("pattern too long (%d chars, max 500)", len(pattern))
	}
	// Go's regexp uses RE2 which is guaranteed linear time — no ReDoS possible
	compiled, err := regexp.Compile("(?i)" + pattern) // case-insensitive
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	return compiled, nil
}

// isExcluded checks if a rule is excluded for the given route/location/field.
func isExcluded(ruleID int, location Location, field string, exclusions []Exclusion) bool {
	for _, e := range exclusions {
		if e.RuleID != ruleID {
			continue
		}
		// Location match: "all" matches everything
		if e.Location != "all" && e.Location != location {
			continue
		}
		// Parameter match: empty means all parameters
		if e.Parameter != "" && e.Parameter != field {
			continue
		}
		return true
	}
	return false
}

// extractSnippet returns up to 200 characters around the match position.
func extractSnippet(content string, endPos, matchLen int) string {
	const maxSnippet = 200
	start := endPos - matchLen + 1
	if start < 0 {
		start = 0
	}

	// Expand context around the match
	contextStart := start - 20
	if contextStart < 0 {
		contextStart = 0
	}
	contextEnd := endPos + 21
	if contextEnd > len(content) {
		contextEnd = len(content)
	}

	snippet := content[contextStart:contextEnd]
	if len(snippet) > maxSnippet {
		snippet = snippet[:maxSnippet]
	}
	return snippet
}
