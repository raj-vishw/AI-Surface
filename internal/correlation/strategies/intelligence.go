package strategies

import (
	"context"

	"ai-surface-platform/internal/correlation"
)

// intelligenceStrategy links an asset (or anything observed on that
// asset) to a Phase 10 intelligence record whose indicator value matches
// the asset's own IP or hostname (phase12.md §17/§21). The intelligence
// record is always labeled as EXTERNAL intelligence in its evidence text
// — never presented as this platform's own observed malicious activity
// (phase12.md §21/§75), matching phase10.md §18/§98's identical
// discipline for Verdict.
type intelligenceStrategy struct{}

// NewIntelligence returns Phase 12's intelligence-context correlation
// strategy.
func NewIntelligence() correlation.Strategy { return intelligenceStrategy{} }

func (intelligenceStrategy) ID() string   { return "intelligence" }
func (intelligenceStrategy) Name() string { return "External Intelligence Context" }
func (intelligenceStrategy) Description() string {
	return "Links an asset (or its observations) to a Phase 10 intelligence record matching its IP/hostname — labeled as external context, never observed activity."
}
func (intelligenceStrategy) Version() int { return 1 }

// intelConfidence maps a Phase 10 Record's own confidence label onto this
// strategy's edge confidence — never upgraded past what the provider
// itself reported.
func intelConfidence(c string) correlation.Confidence {
	switch c {
	case "high":
		return correlation.ConfidenceHigh
	case "medium":
		return correlation.ConfidenceMedium
	default:
		return correlation.ConfidenceLow
	}
}

func (intelligenceStrategy) Evaluate(_ context.Context, input correlation.Input) ([]correlation.Edge, error) {
	var records, others []correlation.Observation
	for _, o := range input.Observations {
		if o.Type == correlation.NodeIntelligenceRecord {
			records = append(records, o)
		} else if o.IP != "" || o.Hostname != "" {
			others = append(others, o)
		}
	}

	var out []correlation.Edge
	for _, rec := range records {
		for _, o := range others {
			if rec.IndicatorValue == "" || (rec.IndicatorValue != o.IP && rec.IndicatorValue != o.Hostname) {
				continue
			}
			verdict := rec.Verdict
			if verdict == "" {
				verdict = "unknown"
			}
			out = append(out, correlation.Edge{
				Source:       correlation.NodeRef{Type: o.Type, ReferenceID: o.ReferenceID},
				Target:       correlation.NodeRef{Type: rec.Type, ReferenceID: rec.ReferenceID},
				Relationship: correlation.RelationshipEnrichedBy, Provenance: correlation.ProvenanceObserved,
				Confidence: intelConfidence(rec.Confidence),
				Evidence: "This observation's indicator (" + rec.IndicatorValue + ") matches an EXTERNAL intelligence record with provider verdict \"" + verdict +
					"\" — a third-party classification, not activity this platform directly observed.",
			})
		}
	}
	return out, nil
}
