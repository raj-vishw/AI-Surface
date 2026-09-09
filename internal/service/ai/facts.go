// Package ai bridges internal/ai's self-contained engine to persistence
// and to Phase 2/7/8/9/10/11/12's own repositories — the same "engine is
// self-contained, the service layer bridges it to the domain model and
// the database" split internal/service/correlation follows for Phase 12.
// It assembles internal/ai.Fact values entirely from data already
// persisted by prior phases (investigations, findings, assets, alerts,
// detection matches, correlations, attack chains, intelligence, risk
// scores, notes) — never from a second, duplicate copy of that data.
package ai

import (
	"fmt"
	"sort"
	"strings"

	"ai-surface-platform/internal/ai"
	domainasset "ai-surface-platform/internal/domain/asset"
	domaincorrelation "ai-surface-platform/internal/domain/correlation"
	domainfinding "ai-surface-platform/internal/domain/finding"
	domainintel "ai-surface-platform/internal/domain/intelligence"
	domaininvestigation "ai-surface-platform/internal/domain/investigation"
	domainrule "ai-surface-platform/internal/domain/rule"
)

// attrs renders a small set of key/value pairs deterministically
// (sorted by key) — used for every Fact.Attributes/Summary suffix so
// output is stable across runs (phase13.md §69's determinism
// requirement) rather than dependent on Go's randomized map iteration.
func attrs(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, m[k]))
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func investigationToFact(inv domaininvestigation.Investigation) ai.Fact {
	a := map[string]string{"status": string(inv.Status), "severity": string(inv.Severity), "priority": string(inv.Priority)}
	return ai.RedactFact(ai.Fact{
		Type: ai.FactInvestigation, ID: inv.ID.String(), Timestamp: inv.CreatedAt,
		Summary: "Investigation: " + inv.Title + attrs(a), Provenance: ai.ProvenanceObserved, Attributes: a,
	})
}

func findingToFact(f domainfinding.Finding) ai.Fact {
	a := map[string]string{"severity": string(f.Severity), "confidence": fmt.Sprintf("%.2f", float64(f.Confidence)), "status": string(f.Status), "category": string(f.Category)}
	return ai.RedactFact(ai.Fact{
		Type: ai.FactFinding, ID: f.ID.String(), Timestamp: f.LastSeen,
		Summary: "Finding: " + f.Title + attrs(a), Provenance: ai.ProvenanceObserved, Attributes: a,
	})
}

func assetToFact(a domainasset.Asset) ai.Fact {
	label := a.IdentityKey
	if a.Hostname != nil && *a.Hostname != "" {
		label = *a.Hostname
	} else if a.IP != nil && *a.IP != "" {
		label = *a.IP
	}
	attributes := map[string]string{"type": string(a.Type), "status": string(a.Status)}
	return ai.RedactFact(ai.Fact{
		Type: ai.FactAsset, ID: a.ID.String(), Timestamp: a.LastSeen,
		Summary: "Asset: " + label + attrs(attributes), Provenance: ai.ProvenanceObserved, Attributes: attributes,
	})
}

func alertToFact(al domainrule.Alert) ai.Fact {
	a := map[string]string{"severity": string(al.Severity), "confidence": string(al.Confidence), "status": string(al.Status)}
	return ai.RedactFact(ai.Fact{
		Type: ai.FactAlert, ID: al.ID.String(), Timestamp: al.LastObservedAt,
		Summary: "Alert: " + al.Title + attrs(a), Provenance: ai.ProvenanceObserved, Attributes: a,
	})
}

func detectionToFact(m domainrule.DetectionMatch, ruleName string) ai.Fact {
	label := ruleName
	if label == "" {
		label = m.RuleID.String()
	}
	a := map[string]string{"severity": string(m.Severity), "confidence": string(m.Confidence), "status": string(m.Status), "rule_version": fmt.Sprintf("%d", m.RuleVersion)}
	return ai.RedactFact(ai.Fact{
		Type: ai.FactDetection, ID: m.ID.String(), Timestamp: m.LastObservedAt,
		Summary: "Detection match for rule '" + label + "': " + m.Explanation + attrs(a), Provenance: ai.ProvenanceObserved, Attributes: a,
	})
}

func correlationToFact(c domaincorrelation.Correlation) ai.Fact {
	a := map[string]string{"severity": string(c.Severity), "confidence": string(c.Confidence), "status": string(c.Status), "score": fmt.Sprintf("%d", c.Score)}
	return ai.RedactFact(ai.Fact{
		Type: ai.FactCorrelation, ID: c.ID.String(), Timestamp: c.LastObservedAt,
		Summary: c.Title + attrs(a), Provenance: ai.ProvenanceObserved, Attributes: a,
	})
}

// correlationNodeFactType maps a persisted correlation node's own type
// vocabulary onto this engine's FactType vocabulary — a small, closed
// table rather than a shared import (internal/ai never imports
// internal/domain/correlation — see internal/ai's own doc comment).
var correlationNodeFactType = map[domaincorrelation.NodeType]ai.FactType{
	domaincorrelation.NodeFinding:            ai.FactFinding,
	domaincorrelation.NodeDetectionMatch:     ai.FactDetection,
	domaincorrelation.NodeAlert:              ai.FactAlert,
	domaincorrelation.NodeAsset:              ai.FactAsset,
	domaincorrelation.NodeEndpoint:           ai.FactEndpoint,
	domaincorrelation.NodeIntelligenceRecord: ai.FactIntelligence,
	domaincorrelation.NodeInvestigation:      ai.FactInvestigation,
}

// correlationNodeToFact renders a correlation graph node using its own
// already-recorded Attributes snapshot (internal/correlation's own
// nodeAttributes flattening — see internal/correlation/graph.go) rather
// than re-querying the underlying finding/asset/alert/... row a second
// time. This is a deliberate efficiency choice, not a shortcut on
// grounding: those attributes are exactly what the correlation engine
// itself observed when it built this node.
func correlationNodeToFact(n domaincorrelation.Node) ai.Fact {
	factType, ok := correlationNodeFactType[n.Type]
	if !ok {
		factType = ai.FactCorrelation
	}
	strAttrs := make(map[string]string, len(n.Attributes))
	for k, v := range n.Attributes {
		strAttrs[k] = fmt.Sprintf("%v", v)
	}
	provenance := ai.ProvenanceObserved
	if n.Role == domaincorrelation.RoleSupporting {
		provenance = ai.ProvenanceInferred
	}
	return ai.RedactFact(ai.Fact{
		Type: factType, ID: n.ReferenceID.String(), Timestamp: n.Timestamp,
		Summary:    fmt.Sprintf("%s %s (role=%s)%s", n.Type, n.ReferenceID, n.Role, attrs(strAttrs)),
		Provenance: provenance, Attributes: strAttrs,
	})
}

func correlationEdgeToFact(e domaincorrelation.Edge) ai.Fact {
	provenance := ai.ProvenanceObserved
	if e.Provenance == domaincorrelation.ProvenanceInferred {
		provenance = ai.ProvenanceInferred
	}
	a := map[string]string{"relationship": string(e.Relationship), "confidence": string(e.Confidence), "strategy": e.StrategyID}
	return ai.RedactFact(ai.Fact{
		Type: ai.FactEdge, ID: e.ID.String(), Timestamp: e.CreatedAt,
		Summary: e.Evidence + attrs(a), Provenance: provenance, Attributes: a,
	})
}

func attackChainToFact(c domaincorrelation.AttackChain) ai.Fact {
	a := map[string]string{"confidence": string(c.Confidence), "severity": string(c.Severity), "status": string(c.Status)}
	return ai.RedactFact(ai.Fact{
		Type: ai.FactAttackChain, ID: c.ID.String(), Timestamp: c.CreatedAt,
		Summary: c.Name + ": " + c.Description + attrs(a), Provenance: ai.ProvenanceInferred, Attributes: a,
	})
}

func attackStageToFact(s domaincorrelation.AttackChainStage) ai.Fact {
	a := map[string]string{"confidence": string(s.Confidence), "order": fmt.Sprintf("%d", s.Order)}
	return ai.RedactFact(ai.Fact{
		Type: ai.FactAttackStage, ID: s.ID.String(), Timestamp: s.CreatedAt,
		Summary: fmt.Sprintf("Stage: %s%s", s.Stage, attrs(a)), Provenance: ai.ProvenanceInferred, Attributes: a,
	})
}

func intelligenceToFact(r domainintel.Record) ai.Fact {
	a := map[string]string{"verdict": string(r.Verdict), "confidence": string(r.Confidence), "provider": r.ProviderID}
	return ai.RedactFact(ai.Fact{
		Type: ai.FactIntelligence, ID: r.ID.String(), Timestamp: r.LastSeen,
		Summary: fmt.Sprintf("%s %s%s", r.IndicatorType, r.IndicatorValue, attrs(a)), Provenance: ai.ProvenanceObserved, Attributes: a,
	})
}

func riskToFact(r domainintel.RiskScore) ai.Fact {
	a := map[string]string{"severity": string(r.Severity), "confidence": string(r.Confidence), "score": fmt.Sprintf("%d", r.Score)}
	return ai.RedactFact(ai.Fact{
		Type: ai.FactRisk, ID: r.EntityID.String(), Timestamp: r.CalculatedAt,
		Summary: fmt.Sprintf("Risk score for %s %s%s", r.EntityType, r.EntityID, attrs(a)), Provenance: ai.ProvenanceObserved, Attributes: a,
	})
}

func timelineEventToFact(e domaininvestigation.TimelineEvent) ai.Fact {
	a := map[string]string{"type": string(e.Type)}
	if e.Severity != "" {
		a["severity"] = e.Severity
	}
	return ai.RedactFact(ai.Fact{
		Type: ai.FactTimelineEvent, ID: e.ID.String(), Timestamp: e.Timestamp,
		Summary: e.Title + attrs(a), Provenance: ai.ProvenanceObserved, Attributes: a,
	})
}

func noteToFact(n domaininvestigation.Note) ai.Fact {
	a := map[string]string{"ai_generated": fmt.Sprintf("%t", n.AIGenerated)}
	return ai.RedactFact(ai.Fact{
		Type: ai.FactNote, ID: n.ID.String(), Timestamp: n.CreatedAt,
		Summary: "Analyst note: " + n.Content + attrs(a), Provenance: ai.ProvenanceObserved, Attributes: a,
	})
}
