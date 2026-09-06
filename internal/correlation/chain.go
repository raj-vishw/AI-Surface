package correlation

import "sort"

// StageType names one generic stage a correlated activity sequence may
// pass through — an independent copy of
// internal/domain/correlation.StageType (this package's own
// zero-domain-dependency vocabulary).
type StageType string

// Recognized attack-chain stages.
const (
	StageInitialActivity   StageType = "initial_activity"
	StageAuthentication    StageType = "authentication"
	StageExecution         StageType = "execution"
	StagePrivilegeChange   StageType = "privilege_change"
	StagePersistenceSignal StageType = "persistence_signal"
	StageDiscoverySignal   StageType = "discovery_signal"
	StageNetworkActivity   StageType = "network_activity"
	StageDataAccess        StageType = "data_access"
	StageImpactSignal      StageType = "impact_signal"
)

// StageDraft is one inferred stage of a ChainDraft, before persistence.
type StageDraft struct {
	Stage      StageType
	Confidence Confidence
	Evidence   []NodeRef
	// earliest is the earliest Evidence timestamp, used only to order
	// stages deterministically — not persisted.
	earliest int64
}

// ChainDraft is BuildChain's output: an ordered, gap-aware stage sequence
// for one connected component (phase12.md §40/§41/§44). A stage this
// component has no evidence for is simply absent from Stages — never
// synthesized (phase12.md §44's "represent an observed gap, or unknown").
type ChainDraft struct {
	Stages     []StageDraft
	Confidence Confidence
}

// classifyStage maps one node's attributes onto a StageType, or ""
// if the node doesn't clearly correspond to any recognized stage — this
// is a best-effort, documented heuristic (phase12.md §41), never a claim
// that the underlying evidence proves a technique occurred. A finding/
// node whose category doesn't match a known pattern deliberately
// contributes no stage rather than being forced into an arbitrary one.
func classifyStage(n Node) (StageType, bool) {
	category, _ := n.Attributes["category"].(string)
	ruleCategory, _ := n.Attributes["rule_category"].(string)
	verdict, _ := n.Attributes["verdict"].(string)

	switch {
	case category == "authentication":
		return StageAuthentication, true
	case n.Ref.Type == NodeIntelligenceRecord && (verdict == "malicious" || verdict == "suspicious"):
		return StageNetworkActivity, true
	case n.Ref.Type == NodeAsset:
		return StageInitialActivity, true
	case n.Ref.Type == NodeEndpoint:
		return StageDiscoverySignal, true
	case category == "exposure" || category == "information_disclosure":
		return StageDiscoverySignal, true
	case n.Ref.Type == NodeDetectionMatch:
		return classifyByKeyword(ruleCategory)
	default:
		return "", false
	}
}

// classifyByKeyword maps a Phase 11 rule category's free-form label onto
// a stage by substring — deliberately conservative, defaulting to
// StageExecution (a detection firing at all is at minimum evidence of
// some executed condition) rather than guessing a more specific,
// unsupported stage.
func classifyByKeyword(ruleCategory string) (StageType, bool) {
	contains := func(needle string) bool {
		for i := 0; i+len(needle) <= len(ruleCategory); i++ {
			if ruleCategory[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	}
	switch {
	case contains("privilege"):
		return StagePrivilegeChange, true
	case contains("persistence"):
		return StagePersistenceSignal, true
	case contains("discovery"):
		return StageDiscoverySignal, true
	case contains("exfil") || contains("data"):
		return StageDataAccess, true
	case contains("impact") || contains("destruct"):
		return StageImpactSignal, true
	case ruleCategory == "":
		return "", false
	default:
		return StageExecution, true
	}
}

// edgeConfidenceTouching returns the highest Confidence among edges with
// ref as either endpoint, or ConfidenceLow if ref has no edges (an
// isolated field_match-style node contributes weak, standalone
// confidence to its stage).
func edgeConfidenceTouching(g Graph, ref NodeRef) Confidence {
	best := ConfidenceLow
	for _, e := range g.Edges {
		if e.Source == ref || e.Target == ref {
			if e.Confidence.rank() > best.rank() {
				best = e.Confidence
			}
		}
	}
	return best
}

// BuildChain infers an ordered stage sequence from component (phase12.md
// §40-45). Nodes that don't classify into any recognized stage
// contribute to the correlation's evidence/graph but not to the chain —
// they are never dropped from the Correlation itself, only omitted from
// this narrower narrative view.
func BuildChain(component Graph) ChainDraft {
	byStage := map[StageType]*StageDraft{}
	var order []StageType

	for _, n := range component.Nodes {
		stage, ok := classifyStage(n)
		if !ok {
			continue
		}
		d, exists := byStage[stage]
		if !exists {
			d = &StageDraft{Stage: stage, earliest: n.Timestamp.UnixNano()}
			byStage[stage] = d
			order = append(order, stage)
		}
		d.Evidence = append(d.Evidence, n.Ref)
		if ts := n.Timestamp.UnixNano(); ts < d.earliest {
			d.earliest = ts
		}
		if c := edgeConfidenceTouching(component, n.Ref); c.rank() > d.Confidence.rank() {
			d.Confidence = c
		}
	}

	stages := make([]StageDraft, 0, len(order))
	for _, s := range order {
		stages = append(stages, *byStage[s])
	}
	sort.Slice(stages, func(i, j int) bool { return stages[i].earliest < stages[j].earliest })

	return ChainDraft{Stages: stages, Confidence: chainConfidence(stages)}
}

// chainConfidence combines every stage's own confidence, weighted by how
// much evidence supports it, rather than a bare average (phase12.md
// §43's "do not simply average arbitrary values"): a stage backed by five
// pieces of evidence should influence the chain's overall confidence more
// than one backed by a single, isolated node.
func chainConfidence(stages []StageDraft) Confidence {
	if len(stages) == 0 {
		return ConfidenceLow
	}
	totalWeight, weightedRank := 0, 0
	for _, s := range stages {
		weight := len(s.Evidence)
		totalWeight += weight
		weightedRank += s.Confidence.rank() * weight
	}
	if totalWeight == 0 {
		return ConfidenceLow
	}
	// Rounded (not truncated) weighted average — a mean of 1.6 should
	// round up to "high" rather than truncate down to "medium".
	avg := (weightedRank*2 + totalWeight) / (2 * totalWeight)
	switch avg {
	case 2:
		return ConfidenceHigh
	case 1:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}
