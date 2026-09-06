// Package risk implements Phase 10's risk-scoring model: a deterministic,
// explainable 0-100 score computed from finding severity, technology
// vulnerability matches, exposure, threat intelligence, asset
// criticality, and recent change (phase10.md §33/§34). It has no
// dependency on any database/repository package — Scorer.Calculate takes
// an in-memory Input assembled by internal/service/intelligence from
// already-persisted data and returns an in-memory Result; the service
// layer maps Result onto internal/domain/intelligence.RiskScore and
// persists it (phase10.md §1).
//
// A risk score is never a claim of confirmed vulnerability — see Result's
// doc comment (phase10.md §35).
package risk

// ModelVersion identifies this package's scoring formula — recorded on
// every Result (phase10.md §43) so a historical score remains
// interpretable even if the formula later changes.
const ModelVersion = "v1"

// Weights are the documented, fixed point values each risk factor may
// contribute (phase10.md §44 — "do not silently change weights"). Every
// value here is deliberately a small integer point cap, not a
// statistical coefficient — see Scorer's doc comment.
type Weights struct {
	// FindingSeverityCritical/High/Medium/Low/Informational are applied
	// once, for the single highest-severity open finding considered
	// (phase10.md §34/§41's "High-severity finding: +30" example).
	FindingSeverityCritical      int
	FindingSeverityHigh          int
	FindingSeverityMedium        int
	FindingSeverityLow           int
	FindingSeverityInformational int
	// FindingConfidenceHigh is added when the contributing finding's own
	// detection confidence is high (phase10.md §41's "High detection
	// confidence: +4").
	FindingConfidenceHigh int

	// ExposureInternetFacing/OpenService/SensitiveEndpoint/ExposedAPI
	// are exposure-surface contributors (phase10.md §37).
	ExposureInternetFacing     int
	ExposureOpenServicePerUnit int
	ExposureOpenServiceMax     int
	ExposureSensitiveEndpoint  int
	ExposureExposedAPI         int

	// VulnerabilityConfirmed/Probable are applied once, for the
	// highest-status vulnerability match considered (phase10.md §38's
	// "Verified technology vulnerability: +20").
	VulnerabilityConfirmed int
	VulnerabilityProbable  int

	// IntelligenceMalicious/Suspicious apply when the aggregated
	// intelligence verdict for a related indicator is malicious/
	// suspicious (phase10.md §34's "reputation signal") — never treated
	// as confirmed malicious activity (phase10.md §35/§98), only as a
	// contextual risk contributor.
	IntelligenceMalicious  int
	IntelligenceSuspicious int

	// AssetCriticality* mirrors internal/domain/intelligence.
	// Criticality.Points() — kept here too (independent copy, same
	// zero-domain-dependency discipline) so risk/ has no dependency on
	// internal/domain/intelligence either.
	AssetCriticalityCritical int
	AssetCriticalityHigh     int
	AssetCriticalityNormal   int
	AssetCriticalityLow      int

	// RecentChange applies when the asset/technology changed recently
	// (phase10.md §34/§41's "Recent change: +10").
	RecentChange int

	// DetectionMatchOpen/DetectionMatchRepeatedPerCount/
	// DetectionMatchRepeatedMax are Phase 11's documented extension to
	// this model (phase11.md §98): DetectionMatchOpen applies once when
	// Input.OpenDetectionMatchCount > 0; DetectionMatchRepeatedPerCount
	// is added per additional open match beyond the first, capped at
	// DetectionMatchRepeatedMax so a large repeated-detection count can
	// never dominate the score.
	DetectionMatchOpen             int
	DetectionMatchRepeatedPerCount int
	DetectionMatchRepeatedMax      int

	// CorrelationOpen/CorrelationRepeatedPerCount/CorrelationRepeatedMax
	// are Phase 12's identically-shaped extension for
	// Input.OpenCorrelationCount (phase12.md §34).
	CorrelationOpen             int
	CorrelationRepeatedPerCount int
	CorrelationRepeatedMax      int
}

// DefaultWeights returns the built-in v1 weighting (phase10.md §41's
// worked example: high-severity finding +30, internet-facing +20,
// verified vulnerable technology +20, recent change +10, high detection
// confidence +4 — sums to 84 in that example).
func DefaultWeights() Weights {
	return Weights{
		FindingSeverityCritical:      40,
		FindingSeverityHigh:          30,
		FindingSeverityMedium:        18,
		FindingSeverityLow:           8,
		FindingSeverityInformational: 2,
		FindingConfidenceHigh:        4,

		ExposureInternetFacing:     20,
		ExposureOpenServicePerUnit: 2,
		ExposureOpenServiceMax:     10,
		ExposureSensitiveEndpoint:  5,
		ExposureExposedAPI:         5,

		VulnerabilityConfirmed: 20,
		VulnerabilityProbable:  10,

		IntelligenceMalicious:  15,
		IntelligenceSuspicious: 7,

		AssetCriticalityCritical: 15,
		AssetCriticalityHigh:     10,
		AssetCriticalityNormal:   0,
		AssetCriticalityLow:      -5,

		RecentChange: 10,

		DetectionMatchOpen:             10,
		DetectionMatchRepeatedPerCount: 2,
		DetectionMatchRepeatedMax:      10,

		CorrelationOpen:             8,
		CorrelationRepeatedPerCount: 2,
		CorrelationRepeatedMax:      8,
	}
}
