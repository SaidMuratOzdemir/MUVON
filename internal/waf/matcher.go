package waf

import (
	"strings"
)

// ExtractParts breaks an HTTP request into ContentParts for WAF inspection.
func ExtractParts(req InspectRequest, maxBodyBytes int) []ContentPart {
	var parts []ContentPart

	// Path
	if req.Path != "" {
		parts = append(parts, ContentPart{
			Content:  req.Path,
			Location: LocPath,
			Field:    "path",
		})
	}

	// Query string
	if req.RawQuery != "" {
		parts = append(parts, ContentPart{
			Content:  req.RawQuery,
			Location: LocQuery,
			Field:    "query",
		})
	}

	// Headers — only inspect security-relevant ones
	inspectHeaders := []string{
		"User-Agent", "Referer", "Cookie", "Origin",
		"X-Forwarded-For", "X-Forwarded-Host",
		"Content-Type", "Accept",
	}
	for _, name := range inspectHeaders {
		val := req.Headers.Get(name)
		if val != "" {
			parts = append(parts, ContentPart{
				Content:  val,
				Location: LocHeader,
				Field:    name,
			})
		}
	}

	// All custom headers (X-* that are not standard forwarding headers)
	for name, values := range req.Headers {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-") && !isStandardForwardHeader(lower) {
			parts = append(parts, ContentPart{
				Content:  strings.Join(values, " "),
				Location: LocHeader,
				Field:    name,
			})
		}
	}

	// Body
	if len(req.Body) > 0 {
		bodyFields := ParseBody(req.Body, req.ContentType, maxBodyBytes)
		for field, content := range bodyFields {
			parts = append(parts, ContentPart{
				Content:  content,
				Location: LocBody,
				Field:    field,
			})
		}
	}

	return parts
}

// MatchAll runs pattern matching against all content parts of a request.
func MatchAll(cache *RuleCache, parts []ContentPart, routeID int, normMaxIter int) []RuleMatch {
	var allMatches []RuleMatch

	for _, part := range parts {
		if part.Content == "" {
			continue
		}

		// Normalize the content to produce multiple variations
		variations := Normalize(part.Content, normMaxIter)
		if len(variations) == 0 {
			continue
		}

		// Run pattern matching against all variations
		matches := cache.Match(variations, part.Location, part.Field, routeID)
		allMatches = append(allMatches, matches...)
	}

	// Deduplicate by rule ID + location + field
	return deduplicateMatches(allMatches)
}

// deduplicateMatches removes duplicate matches (same rule hitting multiple variations).
func deduplicateMatches(matches []RuleMatch) []RuleMatch {
	if len(matches) <= 1 {
		return matches
	}

	type key struct {
		ruleID   int
		location Location
		field    string
	}

	seen := make(map[key]struct{}, len(matches))
	result := make([]RuleMatch, 0, len(matches))

	for _, m := range matches {
		k := key{ruleID: m.RuleID, location: m.Location, field: m.Field}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		result = append(result, m)
	}

	return result
}

func isStandardForwardHeader(lower string) bool {
	switch lower {
	case "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
		"x-real-ip", "x-request-id":
		return true
	}
	return false
}

