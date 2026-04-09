package waf

// AhoCorasick implements the Aho-Corasick multi-pattern string matching algorithm.
// It builds a finite automaton from a set of patterns and scans input in O(n) time,
// finding all occurrences of all patterns in a single pass.
type AhoCorasick struct {
	gotoFn   []map[byte]int // state transitions: state -> byte -> next state
	fail     []int          // failure links for each state
	output   [][]int        // pattern indices that match at each state
	patterns []string       // original lowercase patterns for reference
}

// ACMatch represents a single match found by the Aho-Corasick automaton.
type ACMatch struct {
	PatternIndex int // index into the patterns slice provided to Build
	Position     int // byte offset in the input where the match ends
}

// BuildAhoCorasick constructs an Aho-Corasick automaton from a slice of patterns.
// All patterns are stored as-is; the caller should lowercase them if case-insensitive matching is desired.
func BuildAhoCorasick(patterns []string) *AhoCorasick {
	ac := &AhoCorasick{
		gotoFn:   make([]map[byte]int, 1, len(patterns)*4+1),
		fail:     make([]int, 1, len(patterns)*4+1),
		output:   make([][]int, 1, len(patterns)*4+1),
		patterns: patterns,
	}
	ac.gotoFn[0] = make(map[byte]int)
	ac.output[0] = nil

	// Phase 1: Build the goto function (trie)
	for pi, pattern := range patterns {
		state := 0
		for i := 0; i < len(pattern); i++ {
			ch := pattern[i]
			next, ok := ac.gotoFn[state][ch]
			if !ok {
				next = len(ac.gotoFn)
				ac.gotoFn[state][ch] = next
				ac.gotoFn = append(ac.gotoFn, make(map[byte]int))
				ac.fail = append(ac.fail, 0)
				ac.output = append(ac.output, nil)
			}
			state = next
		}
		ac.output[state] = append(ac.output[state], pi)
	}

	// Phase 2: Build failure links using BFS
	queue := make([]int, 0, len(ac.gotoFn))

	// All depth-1 states fail to root (state 0)
	for _, next := range ac.gotoFn[0] {
		ac.fail[next] = 0
		queue = append(queue, next)
	}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		for ch, next := range ac.gotoFn[curr] {
			queue = append(queue, next)

			// Follow failure links to find the longest proper suffix
			f := ac.fail[curr]
			for f != 0 {
				if _, ok := ac.gotoFn[f][ch]; ok {
					break
				}
				f = ac.fail[f]
			}
			if target, ok := ac.gotoFn[f][ch]; ok && target != next {
				ac.fail[next] = target
			} else {
				ac.fail[next] = 0
			}

			// Merge outputs from the failure chain
			if len(ac.output[ac.fail[next]]) > 0 {
				merged := make([]int, len(ac.output[next]), len(ac.output[next])+len(ac.output[ac.fail[next]]))
				copy(merged, ac.output[next])
				merged = append(merged, ac.output[ac.fail[next]]...)
				ac.output[next] = merged
			}
		}
	}

	return ac
}

// Search scans the input string and returns all pattern matches.
// The input should be lowercase if the automaton was built with lowercase patterns.
func (ac *AhoCorasick) Search(input string) []ACMatch {
	if ac == nil || len(ac.patterns) == 0 {
		return nil
	}

	var matches []ACMatch
	state := 0

	for i := 0; i < len(input); i++ {
		ch := input[i]

		// Follow failure links until we find a valid transition or reach root
		for state != 0 {
			if _, ok := ac.gotoFn[state][ch]; ok {
				break
			}
			state = ac.fail[state]
		}

		if next, ok := ac.gotoFn[state][ch]; ok {
			state = next
		}
		// else state remains 0 (root)

		// Collect all matches at current state
		if len(ac.output[state]) > 0 {
			for _, pi := range ac.output[state] {
				matches = append(matches, ACMatch{
					PatternIndex: pi,
					Position:     i,
				})
			}
		}
	}

	return matches
}

// PatternCount returns the number of patterns in the automaton.
func (ac *AhoCorasick) PatternCount() int {
	if ac == nil {
		return 0
	}
	return len(ac.patterns)
}

// StateCount returns the number of states in the automaton.
func (ac *AhoCorasick) StateCount() int {
	if ac == nil {
		return 0
	}
	return len(ac.gotoFn)
}
