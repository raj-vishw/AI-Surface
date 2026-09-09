// Package builtin provides Phase 11's initial built-in detection rule
// library (phase11.md §74) — a small set of rules that operate ONLY on
// this platform's own already-normalized data (findings, asset/endpoint
// observations, technology fingerprints, threat intelligence records).
// None of them claims to detect a specific real-world threat actor
// (phase11.md §74/§129); each names a pattern, not an attacker.
package builtin

import (
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/ruleengine"
)

// Rule bundles a built-in Definition with the authoring metadata
// internal/domain/rule.Rule/RuleVersion need, plus the documentation
// phase11.md §75/§76 requires (purpose, expected inputs, logic,
// limitations, false-positive guidance) — surfaced by `ai-surface
// detection builtin list` and docs/detection/builtin-rules.md. Tests
// carries this rule's own positive/negative/boundary regression suite
// (phase11.md §52/§119) — every built-in rule must pass its own Tests
// before it can be considered shippable; see builtin_test.go.
type Rule struct {
	Name           string
	Description    string
	Category       string
	Tags           []string
	Purpose        string
	Logic          string
	Limitations    string
	FalsePositives []string
	Definition     ruleengine.Definition
	Tests          []ruleengine.TestCase
}

func newEvent(typ ruleengine.EventType, at time.Time, fields map[string]any) ruleengine.Event {
	return ruleengine.Event{Type: typ, SourceID: uuid.New(), Timestamp: at, Fields: fields}
}

// All returns every built-in rule, in a stable order.
func All() []Rule {
	return []Rule{
		highSeverityFindingBurst(),
		newFindingAfterAssetChange(),
		repeatedMaliciousIntelligence(),
		technologyChangeSpike(),
		criticalExposureFinding(),
	}
}

func highSeverityFindingBurst() Rule {
	return Rule{
		Name:        "high_severity_finding_burst",
		Description: "3 or more high/critical findings on the same asset within 1 hour",
		Category:    "policy", Tags: []string{"suspicious", "reconnaissance"},
		Purpose:     "Surface an asset whose finding history is accumulating high-severity conditions rapidly — often a sign of a genuinely deteriorating security posture, or a detector/scan misconfiguration worth reviewing.",
		Logic:       "Groups findings by asset; fires when 3+ findings with severity in {high, critical} are observed for the same asset within a 1-hour window.",
		Limitations: "Counts findings regardless of detector — a single noisy detector re-firing across several scans can trigger this as easily as three genuinely distinct conditions.",
		FalsePositives: []string{
			"A single misbehaving detector producing several near-duplicate high-severity findings in one scan run",
			"A newly-onboarded asset receiving its first full scan, surfacing several pre-existing conditions at once",
		},
		Definition: ruleengine.Definition{
			EventType: ruleengine.EventFinding,
			Conditions: []ruleengine.Condition{
				{Field: "finding.severity", Operator: ruleengine.OpIn, Value: []any{"high", "critical"}},
				{Field: "finding.status", Operator: ruleengine.OpEquals, Value: "open"},
			},
			RuleType: ruleengine.TypeThreshold, Severity: ruleengine.SeverityHigh, Confidence: ruleengine.ConfidenceMedium,
			SchemaVersion: 1,
			Aggregation: &ruleengine.Aggregation{
				GroupBy: []string{"event.asset_id"}, Window: time.Hour,
				Threshold: ruleengine.Threshold{Operator: ruleengine.ThresholdGreaterThanOrEqual, Value: 3},
			},
		},
		Tests: highSeverityFindingBurstTests(),
	}
}

func highSeverityFindingBurstTests() []ruleengine.TestCase {
	assetID := uuid.New()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	finding := func(offset time.Duration) ruleengine.Event {
		return newEvent(ruleengine.EventFinding, base.Add(offset), map[string]any{
			"event.asset_id": assetID.String(), "finding.severity": "high", "finding.status": "open",
		})
	}
	return []ruleengine.TestCase{
		{Name: "positive: 3 high findings within an hour", ExpectMatchCount: 1, ExpectSeverity: ruleengine.SeverityHigh,
			Events: []ruleengine.Event{finding(0), finding(time.Minute), finding(2 * time.Minute)}},
		{Name: "negative: only 2 high findings", ExpectMatchCount: 0,
			Events: []ruleengine.Event{finding(0), finding(time.Minute)}},
		{Name: "boundary: exactly 3 at the threshold", ExpectMatchCount: 1,
			Events: []ruleengine.Event{finding(0), finding(0), finding(0)}},
	}
}

func newFindingAfterAssetChange() Rule {
	return Rule{
		Name:        "new_finding_after_asset_change",
		Description: "A high-severity finding appears on an asset within 24 hours of that asset being (re-)observed",
		Category:    "reconnaissance", Tags: []string{"suspicious"},
		Purpose:     "Surface a plausible causal link between an asset's own attack surface changing and a new significant finding appearing shortly after — worth an analyst's attention even though this rule cannot establish causation on its own.",
		Logic:       "Sequence: an asset_observation event, followed by a finding event with severity in {high, critical} on the SAME asset, within a 24-hour window.",
		Limitations: "This is a temporal correlation, not a causal one (phase10.md §35's \"risk ≠ vulnerability confirmation\" reasoning applies equally here — a temporal sequence is never presented as proof of cause) — an unrelated finding surfacing shortly after routine re-scanning is common and expected.",
		FalsePositives: []string{
			"Routine periodic re-scanning naturally re-observes an asset immediately before its next scheduled detection pass",
			"Two unrelated changes happening to land within the same 24-hour window by coincidence",
		},
		Definition: ruleengine.Definition{
			EventType: ruleengine.EventFinding, RuleType: ruleengine.TypeSequence,
			Severity: ruleengine.SeverityMedium, Confidence: ruleengine.ConfidenceLow, SchemaVersion: 1,
			Sequence: &ruleengine.Sequence{
				GroupBy: []string{"event.asset_id"}, Window: 24 * time.Hour,
				Steps: []ruleengine.SequenceStep{
					{EventType: ruleengine.EventAssetObservation},
					{EventType: ruleengine.EventFinding, Conditions: []ruleengine.Condition{
						{Field: "finding.severity", Operator: ruleengine.OpIn, Value: []any{"high", "critical"}},
					}},
				},
			},
		},
		Tests: newFindingAfterAssetChangeTests(),
	}
}

func newFindingAfterAssetChangeTests() []ruleengine.TestCase {
	assetID := uuid.New()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	assetObs := func(offset time.Duration) ruleengine.Event {
		return newEvent(ruleengine.EventAssetObservation, base.Add(offset), map[string]any{"event.asset_id": assetID.String()})
	}
	highFinding := func(offset time.Duration) ruleengine.Event {
		return newEvent(ruleengine.EventFinding, base.Add(offset), map[string]any{"event.asset_id": assetID.String(), "finding.severity": "high"})
	}
	return []ruleengine.TestCase{
		{Name: "positive: asset observed then high finding within 24h", ExpectMatchCount: 1,
			Events: []ruleengine.Event{assetObs(0), highFinding(time.Hour)}},
		{Name: "negative: finding before asset observation (wrong order)", ExpectMatchCount: 0,
			Events: []ruleengine.Event{highFinding(0), assetObs(time.Hour)}},
		{Name: "boundary: finding just inside the 24h window", ExpectMatchCount: 1,
			Events: []ruleengine.Event{assetObs(0), highFinding(23*time.Hour + 59*time.Minute)}},
	}
}

func repeatedMaliciousIntelligence() Rule {
	return Rule{
		Name:        "repeated_malicious_intelligence_signal",
		Description: "2 or more intelligence records report a malicious verdict for the same asset within 1 hour",
		Category:    "suspicious", Tags: []string{"suspicious", "policy"},
		Purpose:     "A single provider's malicious verdict is deliberately never treated as confirmed (phase10.md §18/§98); repeated malicious signals across separate lookups raise that context's weight enough to warrant analyst review, without this rule itself claiming confirmation.",
		Logic:       "Groups Phase 10 intelligence records by asset; fires when 2+ records with verdict=malicious are observed for the same asset within a 1-hour window.",
		Limitations: "Does not distinguish which provider(s) reported malicious — see the underlying intelligence_records rows for full provenance before acting.",
		FalsePositives: []string{
			"An intelligence provider re-confirming the same finding across a scheduled refresh, counted as if it were an independent signal",
			"A provider's own false-positive rate for the indicator category involved",
		},
		Definition: ruleengine.Definition{
			EventType:  ruleengine.EventIntelligenceRecord,
			Conditions: []ruleengine.Condition{{Field: "intelligence.verdict", Operator: ruleengine.OpEquals, Value: "malicious"}},
			RuleType:   ruleengine.TypeThreshold, Severity: ruleengine.SeverityHigh, Confidence: ruleengine.ConfidenceMedium, SchemaVersion: 1,
			Aggregation: &ruleengine.Aggregation{
				GroupBy: []string{"event.asset_id"}, Window: time.Hour,
				Threshold: ruleengine.Threshold{Operator: ruleengine.ThresholdGreaterThanOrEqual, Value: 2},
			},
		},
		Tests: repeatedMaliciousIntelligenceTests(),
	}
}

func repeatedMaliciousIntelligenceTests() []ruleengine.TestCase {
	assetID := uuid.New()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	record := func(verdict string, offset time.Duration) ruleengine.Event {
		return newEvent(ruleengine.EventIntelligenceRecord, base.Add(offset), map[string]any{
			"event.asset_id": assetID.String(), "intelligence.verdict": verdict,
		})
	}
	return []ruleengine.TestCase{
		{Name: "positive: 2 malicious records within an hour", ExpectMatchCount: 1,
			Events: []ruleengine.Event{record("malicious", 0), record("malicious", time.Minute)}},
		{Name: "negative: 1 malicious, 1 benign", ExpectMatchCount: 0,
			Events: []ruleengine.Event{record("malicious", 0), record("benign", time.Minute)}},
		{Name: "boundary: exactly 2 at the threshold", ExpectMatchCount: 1,
			Events: []ruleengine.Event{record("malicious", 0), record("malicious", 0)}},
	}
}

func technologyChangeSpike() Rule {
	return Rule{
		Name:        "technology_change_spike",
		Description: "3 or more distinct technologies newly fingerprinted on the same asset within 10 minutes",
		Category:    "reconnaissance", Tags: []string{"reconnaissance", "policy"},
		Purpose:     "A sudden burst of distinct technology fingerprints on one asset often indicates a significant, worth-reviewing infrastructure change (a migration, a new deployment, or a misconfigured/rotating proxy).",
		Logic:       "Groups Phase 6 fingerprint-change events by asset; fires when 3+ DISTINCT technology values are observed for the same asset within a 10-minute window (unique_count, not a raw count).",
		Limitations: "A single re-scan that simply re-confirms several already-known technologies at once can also trigger this if those technologies were only just fingerprinted for the first time in this run.",
		FalsePositives: []string{
			"The very first fingerprinting pass against a newly-onboarded asset, which legitimately identifies several technologies at once",
			"A load balancer or CDN fronting several distinct backend technologies simultaneously",
		},
		Definition: ruleengine.Definition{
			EventType: ruleengine.EventFingerprintChange, RuleType: ruleengine.TypeAggregation,
			Severity: ruleengine.SeverityLow, Confidence: ruleengine.ConfidenceMedium, SchemaVersion: 1,
			Aggregation: &ruleengine.Aggregation{
				GroupBy: []string{"event.asset_id"}, Window: 10 * time.Minute,
				Function: ruleengine.FunctionUniqueCount, UniqueField: "fingerprint.technology",
				Threshold: ruleengine.Threshold{Operator: ruleengine.ThresholdGreaterThanOrEqual, Value: 3},
			},
		},
		Tests: technologyChangeSpikeTests(),
	}
}

func technologyChangeSpikeTests() []ruleengine.TestCase {
	assetID := uuid.New()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tech := func(name string, offset time.Duration) ruleengine.Event {
		return newEvent(ruleengine.EventFingerprintChange, base.Add(offset), map[string]any{
			"event.asset_id": assetID.String(), "fingerprint.technology": name,
		})
	}
	return []ruleengine.TestCase{
		{Name: "positive: 3 distinct technologies within 10 minutes", ExpectMatchCount: 1,
			Events: []ruleengine.Event{tech("nginx", 0), tech("react", time.Minute), tech("postgresql", 2*time.Minute)}},
		{Name: "negative: same technology repeated is not 3 distinct", ExpectMatchCount: 0,
			Events: []ruleengine.Event{tech("nginx", 0), tech("nginx", time.Minute), tech("nginx", 2*time.Minute)}},
		{Name: "boundary: exactly 3 distinct at the threshold", ExpectMatchCount: 1,
			Events: []ruleengine.Event{tech("a", 0), tech("b", 0), tech("c", 0)}},
	}
}

func criticalExposureFinding() Rule {
	return Rule{
		Name:        "critical_exposure_finding",
		Description: "Any single finding categorized as an exposure with critical severity",
		Category:    "web", Tags: []string{"web", "policy"},
		Purpose:     "Immediately surface the single most severe, highest-priority class of finding this platform already detects (Phase 8's exposure/information-disclosure detectors), without waiting for any aggregation window.",
		Logic:       "field_match: a single finding event with category=exposure AND severity=critical is itself the match — no grouping or window involved.",
		Limitations: "Entirely dependent on Phase 8's own detectors correctly classifying category/severity — this rule adds no additional evidence beyond what the finding itself already carries.",
		FalsePositives: []string{
			"An accepted-risk condition that hasn't yet been marked accepted_risk/false_positive in Phase 8",
		},
		Definition: ruleengine.Definition{
			EventType: ruleengine.EventFinding,
			Conditions: []ruleengine.Condition{
				{Field: "finding.category", Operator: ruleengine.OpEquals, Value: "exposure"},
				{Field: "finding.severity", Operator: ruleengine.OpEquals, Value: "critical"},
				{Field: "finding.status", Operator: ruleengine.OpEquals, Value: "open"},
			},
			RuleType: ruleengine.TypeFieldMatch, Severity: ruleengine.SeverityCritical, Confidence: ruleengine.ConfidenceHigh, SchemaVersion: 1,
		},
		Tests: criticalExposureFindingTests(),
	}
}

func criticalExposureFindingTests() []ruleengine.TestCase {
	now := time.Now()
	finding := func(category, severity, status string) ruleengine.Event {
		return newEvent(ruleengine.EventFinding, now, map[string]any{
			"finding.category": category, "finding.severity": severity, "finding.status": status,
		})
	}
	return []ruleengine.TestCase{
		{Name: "positive: critical open exposure finding", ExpectMatchCount: 1, ExpectSeverity: ruleengine.SeverityCritical,
			Events: []ruleengine.Event{finding("exposure", "critical", "open")}},
		{Name: "negative: high (not critical) exposure finding", ExpectMatchCount: 0,
			Events: []ruleengine.Event{finding("exposure", "high", "open")}},
		{Name: "boundary: critical exposure finding that is already resolved", ExpectMatchCount: 0,
			Events: []ruleengine.Event{finding("exposure", "critical", "resolved")}},
	}
}
