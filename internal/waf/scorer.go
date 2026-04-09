package waf

import (
	"math"
	"time"
)

// ScoreRequest calculates the total threat score for a single request
// by summing all matched rule severities.
func ScoreRequest(matches []RuleMatch) int {
	total := 0
	for _, m := range matches {
		total += m.Severity
	}
	return total
}

// AddHit records a new request score in the IP's sliding window and recalculates
// the cumulative IP score with exponential time decay.
//
// The decay formula: contribution = score × e^(-decayRate × hoursAgo)
// where decayRate = decayPerHour / 10.0 (so decay_per_hour=5.0 means ~61% remains after 1 hour).
//
// Hits outside the sliding window are evicted.
func (s *IPState) AddHit(requestScore int, now time.Time, windowHours int, decayPerHour float64) float64 {
	if requestScore > 0 {
		s.Hits = append(s.Hits, ScoredHit{
			Score:     requestScore,
			Timestamp: now,
		})
	}

	s.LastSeen = now
	s.Dirty = true

	return s.RecalculateScore(now, windowHours, decayPerHour)
}

// RecalculateScore evicts expired hits and computes the cumulative score with decay.
func (s *IPState) RecalculateScore(now time.Time, windowHours int, decayPerHour float64) float64 {
	cutoff := now.Add(-time.Duration(windowHours) * time.Hour)

	// Evict old hits
	kept := s.Hits[:0]
	for _, h := range s.Hits {
		if h.Timestamp.After(cutoff) {
			kept = append(kept, h)
		}
	}
	s.Hits = kept

	// Calculate cumulative score with exponential decay
	decayRate := decayPerHour / 10.0
	var cumulative float64
	for _, h := range s.Hits {
		hoursAgo := now.Sub(h.Timestamp).Hours()
		weight := math.Exp(-decayRate * hoursAgo)
		cumulative += float64(h.Score) * weight
	}

	s.CumulativeScore = cumulative
	return cumulative
}

// DetermineAction maps a cumulative IP score to a graduated action
// based on configurable thresholds.
//
// Default thresholds:
//
//	0-10:    log (observe only)
//	11-25:   rate_limit (slow down)
//	26-50:   block (403 this request)
//	51-100:  temp_ban (ban for configured duration)
//	101+:    ban (long-term ban)
func DetermineAction(ipScore float64, cfg *WafConfig) Action {
	score := int(ipScore)
	switch {
	case score >= cfg.ThresholdBan:
		return ActionBan
	case score >= cfg.ThresholdTempBan:
		return ActionTempBan
	case score >= cfg.ThresholdBlock:
		return ActionBlock
	case score >= cfg.ThresholdRateLimit:
		return ActionRateLimit
	case score > cfg.ThresholdLog:
		return ActionLog
	default:
		return ActionAllow
	}
}

// BuildBlockReason constructs a human-readable block reason from the highest-severity match.
func BuildBlockReason(matches []RuleMatch) string {
	if len(matches) == 0 {
		return ""
	}

	// Find highest severity match
	best := matches[0]
	for _, m := range matches[1:] {
		if m.Severity > best.Severity {
			best = m
		}
	}

	return string(best.Category) + "_IN_" + string(best.Location)
}
