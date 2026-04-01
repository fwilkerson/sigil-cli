// Package trustclient provides trust-check and attestation logic for agent
// integrations. It contains the domain logic — recommendation thresholds,
// parameter shape extraction, and session rate limiting — while delegating
// I/O to a [TrustQuerier] interface that callers implement.
package trustclient

// Recommendation is the agent-facing trust verdict for a tool.
type Recommendation string

// Defined recommendation values.
const (
	// RecommendUse means the tool is well-trusted (score >= 0.7).
	RecommendUse Recommendation = "use"

	// RecommendCaution means limited data or mixed reviews (0.3 <= score < 0.7),
	// or the score is provisional regardless of numeric value.
	RecommendCaution Recommendation = "caution"

	// RecommendAvoid means the tool is poorly trusted (score < 0.3).
	RecommendAvoid Recommendation = "avoid"

	// RecommendUnknown means no attestations exist — different from "bad."
	RecommendUnknown Recommendation = "unknown"
)

// Recommend returns a recommendation and human-readable label based on the
// trust score, attestation count, and provisional flag.
//
// Threshold logic:
//   - score >= 0.7 → "use" (well-trusted)
//   - 0.3 <= score < 0.7 → "caution" (limited data or mixed reviews)
//   - score < 0.3 → "avoid" (poorly trusted)
//   - No data → "unknown" (no attestations yet)
//   - Provisional → "caution" with "(provisional — limited data)" label
func Recommend(score float64, totalAttestations int, provisional bool) (Recommendation, string) {
	if totalAttestations == 0 {
		return RecommendUnknown, "unknown — no attestations yet"
	}
	if provisional {
		return RecommendCaution, "caution (provisional — limited data)"
	}
	switch {
	case score >= 0.7:
		return RecommendUse, "well-trusted"
	case score >= 0.3:
		return RecommendCaution, "limited data or mixed reviews"
	default:
		return RecommendAvoid, "poorly trusted"
	}
}
