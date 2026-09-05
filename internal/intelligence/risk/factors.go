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
}
