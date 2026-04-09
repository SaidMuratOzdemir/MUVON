package waf

import (
	"html"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// maxVariations caps the total number of normalized variations to prevent excessive work.
const maxVariations = 12

// Normalize produces deduplicated content variations from a single input string.
// Each variation is a different normalization path, maximizing detection of encoding bypasses.
// The input is lowercased first; then URL decoding, HTML entity decoding, Unicode normalization,
// comment stripping, and whitespace normalization are applied iteratively and in combinations.
func Normalize(input string, maxIterations int) []string {
	if input == "" {
		return nil
	}
	if maxIterations <= 0 {
		maxIterations = 3
	}

	seen := make(map[string]struct{}, maxVariations)
	result := make([]string, 0, maxVariations)

	add := func(s string) {
		if len(result) >= maxVariations {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		result = append(result, s)
	}

	lowered := strings.ToLower(input)
	add(lowered)

	// 1. Iterative URL decode
	urlDecoded := iterativeDecode(lowered, maxIterations, urlDecode)
	add(urlDecoded)

	// 2. Iterative URL decode with plus-as-space
	urlPlusDecoded := iterativeDecode(lowered, maxIterations, urlDecodePlus)
	add(urlPlusDecoded)

	// 3. HTML entity decode
	htmlDecoded := iterativeDecode(lowered, maxIterations, html.UnescapeString)
	add(htmlDecoded)

	// 4. Unicode NFKC normalization (fullwidth → ASCII, compatibility decomposition)
	unicodeNorm := unicodeNFKC(lowered)
	add(unicodeNorm)

	// 5. Combined: URL decode → HTML decode → Unicode normalize
	combined1 := unicodeNFKC(html.UnescapeString(urlDecoded))
	add(combined1)

	// 6. Combined: HTML decode → URL decode → Unicode normalize
	combined2 := unicodeNFKC(iterativeDecode(htmlDecoded, maxIterations, urlDecode))
	add(combined2)

	// 7. Strip comments from the most-decoded form
	stripped := stripComments(combined1)
	add(stripped)

	// 8. Whitespace normalized form
	wsNorm := normalizeWhitespace(combined1)
	add(wsNorm)

	// 9. Null bytes removed
	nullRemoved := removeNullBytes(combined1)
	add(nullRemoved)

	// 10. Full pipeline: all transformations combined
	full := normalizeWhitespace(removeNullBytes(stripComments(combined1)))
	add(full)

	return result
}

// iterativeDecode applies a decode function repeatedly until the output stabilizes
// or maxIter is reached.
func iterativeDecode(input string, maxIter int, decode func(string) string) string {
	prev := input
	for i := 0; i < maxIter; i++ {
		decoded := decode(prev)
		if decoded == prev {
			break
		}
		prev = decoded
	}
	return prev
}

// urlDecode decodes percent-encoded sequences including Unicode %uXXXX.
func urlDecode(s string) string {
	// First handle IIS-style %uXXXX encoding
	s = decodePercentU(s)
	// Standard URL decoding
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return decoded
}

// urlDecodePlus decodes percent-encoded sequences and '+' as space.
func urlDecodePlus(s string) string {
	s = decodePercentU(s)
	decoded, err := url.QueryUnescape(strings.ReplaceAll(s, "+", " "))
	if err != nil {
		return s
	}
	return decoded
}

// decodePercentU handles IIS-style %uXXXX Unicode encoding.
var percentURe = regexp.MustCompile(`(?i)%u([0-9a-f]{4})`)

func decodePercentU(s string) string {
	return percentURe.ReplaceAllStringFunc(s, func(match string) string {
		hex := match[2:]
		var r rune
		for _, c := range hex {
			r <<= 4
			switch {
			case c >= '0' && c <= '9':
				r |= rune(c - '0')
			case c >= 'a' && c <= 'f':
				r |= rune(c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				r |= rune(c - 'A' + 10)
			}
		}
		return string(r)
	})
}

// unicodeNFKC applies Unicode NFKC normalization and strips zero-width characters.
func unicodeNFKC(s string) string {
	normalized := norm.NFKC.String(s)
	// Remove zero-width characters (U+200B, U+200C, U+200D, U+FEFF)
	return strings.Map(func(r rune) rune {
		switch r {
		case '\u200B', '\u200C', '\u200D', '\uFEFF':
			return -1
		default:
			return r
		}
	}, normalized)
}

// stripComments removes common comment syntaxes used in bypass attempts.
func stripComments(s string) string {
	// Remove C-style block comments: /* ... */
	result := removeBetween(s, "/*", "*/")
	// Remove HTML comments: <!-- ... -->
	result = removeBetween(result, "<!--", "-->")
	return result
}

// removeBetween removes all occurrences of content between open and close markers (inclusive).
func removeBetween(s, open, close string) string {
	var b strings.Builder
	b.Grow(len(s))
	for {
		idx := strings.Index(s, open)
		if idx == -1 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:idx])
		rest := s[idx+len(open):]
		endIdx := strings.Index(rest, close)
		if endIdx == -1 {
			// No closing marker — remove to end
			break
		}
		s = rest[endIdx+len(close):]
	}
	return b.String()
}

// normalizeWhitespace collapses multiple whitespace characters into a single space
// and trims leading/trailing whitespace.
func normalizeWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inSpace := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			if !inSpace {
				b.WriteByte(' ')
				inSpace = true
			}
		} else {
			b.WriteRune(r)
			inSpace = false
		}
	}
	return strings.TrimSpace(b.String())
}

// removeNullBytes strips null bytes and other control characters used in bypass attempts.
func removeNullBytes(s string) string {
	return strings.Map(func(r rune) rune {
		if r == 0 {
			return -1
		}
		return r
	}, s)
}

// HasEncodingBypassIndicators checks if content contains encoding patterns commonly
// used in WAF bypass attempts. Used as a fast pre-check.
func HasEncodingBypassIndicators(s string) bool {
	lower := strings.ToLower(s)
	indicators := []string{
		// URL encoding
		"%3c", "%3e", "%22", "%27", "%2b", "%20", "%00",
		// Double encoding
		"%253c", "%253e", "%2522",
		// HTML entities
		"&lt;", "&gt;", "&quot;", "&#x", "&#",
		// Unicode
		"\\u00", "\\x", "%u00",
	}
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}
