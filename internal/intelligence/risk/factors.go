package risk

// Severity mirrors internal/intelligence's vocabulary — an independent
// copy (this package has no dependency on internal/intelligence or
// internal/domain/intelligence, matching the zero-dependency discipline
// internal/detection/internal/investigation establish for their own
// engines). VulnerabilityStatus/IntelligenceVerdict/Criticality below
// are the same kind of independent copy.
type Severity string

// Recognized finding/vulnerability severities considered by the model.
const (
	SeverityInformational Severity = "informational"
	SeverityLow           Severity = "low"
	SeverityMedium        Severity = "medium"
	SeverityHigh          Severity = "high"
	SeverityCritical      Severity = "critical"
)

// VulnerabilityStatus narrows the vulnerability match statuses that
// affect risk — MatchInsufficientEvidence/MatchNone never contribute
// (phase10.md §35's "risk ≠ vulnerability" boundary: an unconfirmed match
// must not inflate risk as if it were confirmed).
type VulnerabilityStatus string

// Recognized statuses.
const (
	VulnerabilityConfirmed VulnerabilityStatus = "confirmed"
	VulnerabilityProbable  VulnerabilityStatus = "probable"
	VulnerabilityNone      VulnerabilityStatus = "" // no contributing match
)

// IntelligenceVerdict narrows the aggregated intelligence verdicts that
// affect risk.
type IntelligenceVerdict string

// Recognized verdicts.
const (
	IntelligenceMalicious  IntelligenceVerdict = "malicious"
	IntelligenceSuspicious IntelligenceVerdict = "suspicious"
	IntelligenceBenign     IntelligenceVerdict = "benign"
	IntelligenceUnknown    IntelligenceVerdict = "unknown"
)

// Criticality mirrors internal/domain/intelligence.Criticality.
type Criticality string

// Recognized criticality levels.
const (
	CriticalityLow      Criticality = "low"
	CriticalityNormal   Criticality = "normal"
	CriticalityHigh     Criticality = "high"
	CriticalityCritical Criticality = "critical"
)

// Input is everything the risk model needs for one calculation — always
// assembled from data already persisted elsewhere (findings, vulnerability
// matches, aggregated intelligence, asset exposure/criticality), never
// fabricated (phase10.md §34: "only include factors supported by actual
// data").
type Input struct {
	// HighestFindingSeverity/HighestFindingConfidenceHigh describe the
	// single highest-severity OPEN finding under consideration
	// (phase10.md §41's example scores one finding, not a sum over
	// every finding — summing severities would let ten low findings
	// outscore one critical one, which is not the intent).
	HighestFindingSeverity       Severity
	HighestFindingConfidenceHigh bool

	InternetFacing         bool
	OpenServiceCount       int
	SensitiveEndpointCount int
	ExposedAPI             bool

	// HighestVulnerabilityStatus is the strongest vulnerability match
	// status under consideration, VulnerabilityNone if none apply.
	HighestVulnerabilityStatus VulnerabilityStatus

	IntelligenceVerdict IntelligenceVerdict

	AssetCriticality Criticality

	RecentChange bool

	// OpenDetectionMatchCount is how many open Phase 11 detection-rule
	// matches currently exist for this asset — a documented, additive
	// risk factor (phase11.md §98): a non-zero count contributes once
	// (the asset has at least one active detection), plus a small
	// per-match increment capped at
	// Weights.DetectionMatchRepeatedMax so a large repeated-detection
	// count can never dominate the score on its own. This never
	// duplicates Phase 10's own risk calculator — it is a value Phase
	// 11's service supplies into this same Input (see
	// internal/service/intelligence's optional detection-match wiring).
	OpenDetectionMatchCount int

	// OpenCorrelationCount is how many open (non-dismissed) Phase 12
	// correlations currently reference this asset — a documented,
	// additive risk factor (phase12.md §34) following the identical
	// "one flat contribution plus a small, capped per-item increment"
	// shape phase11.md §98 established for OpenDetectionMatchCount above.
	// This never duplicates Phase 12's own correlation scoring
	// (internal/correlation.Score answers a different question — how
	// strong is this specific grouping's own evidence — from this
	// asset-level risk factor, which only counts how many such groupings
	// currently touch the asset at all).
	OpenCorrelationCount int
}
