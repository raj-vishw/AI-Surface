package risk

import "fmt"

// Confidence is the model's overall confidence in a Result — leveled,
// not numeric, matching internal/intelligence.Confidence's rationale
// (phase10.md §55).
type Confidence string

// Recognized confidence levels.
const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Factor is one named, scored contributor to a Result — every score must
// explain itself (phase10.md §41).
type Factor struct {
	Name        string
	Points      int
	Description string
}

// Result is one Scorer.Calculate call's outcome. IMPORTANT: Score is a
// combined security-context signal, never a claim of confirmed
// vulnerability (phase10.md §35) — findings, intelligence, and risk
// remain separate concepts throughout this platform.
type Result struct {
	Score        int // clamped to [0, 100] — phase10.md §42
	Severity     Severity
	Confidence   Confidence
	ModelVersion string
	Factors      []Factor
	Explanation  string
}

// Scorer computes a Result from an Input using a fixed Weights table
// (phase10.md §33/§44).
type Scorer struct {
	weights Weights
}

// NewScorer builds a Scorer. A zero Weights uses DefaultWeights.
func NewScorer(weights Weights) *Scorer {
	if weights == (Weights{}) {
		weights = DefaultWeights()
	}
	return &Scorer{weights: weights}
}

// Calculate deterministically scores input (phase10.md §84: same input
// always produces the same score). The result is always clamped to
// [0, 100] (phase10.md §42) regardless of how many factors fire.
func (s *Scorer) Calculate(input Input) Result {
	var factors []Factor
	raw := 0

	if pts := s.findingSeverityPoints(input.HighestFindingSeverity); pts != 0 {
		factors = append(factors, Factor{Name: "finding_severity", Points: pts,
			Description: fmt.Sprintf("highest open finding severity: %s", input.HighestFindingSeverity)})
		raw += pts
	}
	if input.HighestFindingConfidenceHigh && s.weights.FindingConfidenceHigh != 0 {
		factors = append(factors, Factor{Name: "finding_confidence", Points: s.weights.FindingConfidenceHigh,
			Description: "high detection confidence on the contributing finding"})
		raw += s.weights.FindingConfidenceHigh
	}

	if input.InternetFacing && s.weights.ExposureInternetFacing != 0 {
		factors = append(factors, Factor{Name: "internet_exposure", Points: s.weights.ExposureInternetFacing,
			Description: "asset is internet-facing"})
		raw += s.weights.ExposureInternetFacing
	}
	if input.OpenServiceCount > 0 && s.weights.ExposureOpenServicePerUnit != 0 {
		pts := input.OpenServiceCount * s.weights.ExposureOpenServicePerUnit
		if s.weights.ExposureOpenServiceMax > 0 && pts > s.weights.ExposureOpenServiceMax {
			pts = s.weights.ExposureOpenServiceMax
		}
		factors = append(factors, Factor{Name: "open_services", Points: pts,
			Description: fmt.Sprintf("%d open service(s) observed", input.OpenServiceCount)})
		raw += pts
	}
	if input.SensitiveEndpointCount > 0 && s.weights.ExposureSensitiveEndpoint != 0 {
		factors = append(factors, Factor{Name: "sensitive_endpoints", Points: s.weights.ExposureSensitiveEndpoint,
			Description: fmt.Sprintf("%d sensitive endpoint(s) observed", input.SensitiveEndpointCount)})
		raw += s.weights.ExposureSensitiveEndpoint
	}
	if input.ExposedAPI && s.weights.ExposureExposedAPI != 0 {
		factors = append(factors, Factor{Name: "exposed_api", Points: s.weights.ExposureExposedAPI,
			Description: "an API surface is exposed"})
		raw += s.weights.ExposureExposedAPI
	}

	switch input.HighestVulnerabilityStatus {
	case VulnerabilityConfirmed:
		factors = append(factors, Factor{Name: "vulnerability_match", Points: s.weights.VulnerabilityConfirmed,
			Description: "confirmed technology vulnerability match"})
		raw += s.weights.VulnerabilityConfirmed
	case VulnerabilityProbable:
		factors = append(factors, Factor{Name: "vulnerability_match", Points: s.weights.VulnerabilityProbable,
			Description: "probable technology vulnerability match"})
		raw += s.weights.VulnerabilityProbable
	}

	switch input.IntelligenceVerdict {
	case IntelligenceMalicious:
		factors = append(factors, Factor{Name: "threat_intelligence", Points: s.weights.IntelligenceMalicious,
			Description: "aggregated intelligence verdict: malicious (provider classification, not confirmed activity)"})
		raw += s.weights.IntelligenceMalicious
	case IntelligenceSuspicious:
		factors = append(factors, Factor{Name: "threat_intelligence", Points: s.weights.IntelligenceSuspicious,
			Description: "aggregated intelligence verdict: suspicious"})
		raw += s.weights.IntelligenceSuspicious
	}

	if pts := s.criticalityPoints(input.AssetCriticality); pts != 0 {
		factors = append(factors, Factor{Name: "asset_criticality", Points: pts,
			Description: fmt.Sprintf("asset criticality: %s", input.AssetCriticality)})
		raw += pts
	}

	if input.RecentChange && s.weights.RecentChange != 0 {
		factors = append(factors, Factor{Name: "recent_change", Points: s.weights.RecentChange,
			Description: "asset or technology changed recently"})
		raw += s.weights.RecentChange
	}

	if input.OpenDetectionMatchCount > 0 {
		pts := s.weights.DetectionMatchOpen
		repeated := (input.OpenDetectionMatchCount - 1) * s.weights.DetectionMatchRepeatedPerCount
		if s.weights.DetectionMatchRepeatedMax > 0 && repeated > s.weights.DetectionMatchRepeatedMax {
			repeated = s.weights.DetectionMatchRepeatedMax
		}
		pts += repeated
		if pts != 0 {
			factors = append(factors, Factor{Name: "detection_match", Points: pts,
				Description: fmt.Sprintf("%d open Phase 11 detection match(es) on this asset", input.OpenDetectionMatchCount)})
			raw += pts
		}
	}

	if input.OpenCorrelationCount > 0 {
		pts := s.weights.CorrelationOpen
		repeated := (input.OpenCorrelationCount - 1) * s.weights.CorrelationRepeatedPerCount
		if s.weights.CorrelationRepeatedMax > 0 && repeated > s.weights.CorrelationRepeatedMax {
			repeated = s.weights.CorrelationRepeatedMax
		}
		pts += repeated
		if pts != 0 {
			factors = append(factors, Factor{Name: "correlation", Points: pts,
				Description: fmt.Sprintf("%d open Phase 12 correlation(s) reference this asset", input.OpenCorrelationCount)})
			raw += pts
		}
	}

	score := clamp(raw, 0, 100)
	severity := SeverityForScore(score)
	confidence := s.confidenceFor(input)

	return Result{
		Score: score, Severity: severity, Confidence: confidence,
		ModelVersion: ModelVersion, Factors: factors, Explanation: explain(score, factors),
	}
}

func (s *Scorer) findingSeverityPoints(sev Severity) int {
	switch sev {
	case SeverityCritical:
		return s.weights.FindingSeverityCritical
	case SeverityHigh:
		return s.weights.FindingSeverityHigh
	case SeverityMedium:
		return s.weights.FindingSeverityMedium
	case SeverityLow:
		return s.weights.FindingSeverityLow
	case SeverityInformational:
		return s.weights.FindingSeverityInformational
	default:
		return 0
	}
}

func (s *Scorer) criticalityPoints(c Criticality) int {
	switch c {
	case CriticalityCritical:
		return s.weights.AssetCriticalityCritical
	case CriticalityHigh:
		return s.weights.AssetCriticalityHigh
	case CriticalityLow:
		return s.weights.AssetCriticalityLow
	default:
		return s.weights.AssetCriticalityNormal
	}
}

// confidenceFor derives the model's confidence in its own Result from
// how much real evidence fed into it — an input with no contributing
// factors at all is reported at low confidence rather than a
// deceptively-precise score with nothing behind it.
func (s *Scorer) confidenceFor(input Input) Confidence {
	signals := 0
	if input.HighestFindingSeverity != "" {
		signals++
	}
	if input.HighestVulnerabilityStatus != VulnerabilityNone {
		signals++
	}
	if input.IntelligenceVerdict != "" && input.IntelligenceVerdict != IntelligenceUnknown {
		signals++
	}
	if input.OpenDetectionMatchCount > 0 {
		signals++
	}
	if input.OpenCorrelationCount > 0 {
		signals++
	}
	switch {
	case signals >= 2:
		return ConfidenceHigh
	case signals == 1:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

// SeverityForScore buckets a 0-100 score into a named severity —
// identical boundaries to internal/domain/intelligence.
// RiskSeverityForScore, kept as an independent copy.
func SeverityForScore(score int) Severity {
	switch {
	case score >= 75:
		return SeverityCritical
	case score >= 50:
		return SeverityHigh
	case score >= 25:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func explain(score int, factors []Factor) string {
	if len(factors) == 0 {
		return fmt.Sprintf("Risk Score: %d — no contributing risk factors were found in currently available data", score)
	}
	out := fmt.Sprintf("Risk Score: %d\n\nFactors:", score)
	for _, f := range factors {
		sign := "+"
		if f.Points < 0 {
			sign = ""
		}
		out += fmt.Sprintf("\n    %s: %s%d", f.Description, sign, f.Points)
	}
	return out
}
