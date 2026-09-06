package correlation

// severityRank orders this platform's shared five-level severity
// vocabulary (informational..critical, the same scale
// internal/domain/finding.Severity/internal/domain/rule.Severity use) for
// comparison — an independent copy, since a Node's "severity" attribute
// is a plain string (this package never imports a domain package).
var severityRank = map[string]int{
	"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

var rankSeverity = []string{"informational", "low", "medium", "high", "critical"}

// edgeConfidencePoints weights one Edge's contribution to Score by its
// own Confidence — deliberately modest even at "high", since no single
// edge should alone push a correlation to a high score (phase12.md §31's
// "the score should reflect... not a single signal").
var edgeConfidencePoints = map[Confidence]int{ConfidenceLow: 5, ConfidenceMedium: 10, ConfidenceHigh: 18}

// Score computes component's 0-100 correlation score (phase12.md §31).
// The formula, documented here rather than left implicit:
//
//  1. A base of 15 points once component has more than one node — a
//     single, unconnected observation cannot itself be "correlated".
//  2. Each edge contributes edgeConfidencePoints[edge.Confidence],
//     capped at 40 total so a large but shallow graph cannot alone reach
//     a maximal score.
//  3. +8 for every distinct node type present (capped at 24) — a
//     correlation spanning findings+detections+intelligence is stronger
//     evidence than many nodes of the same type.
//  4. +6 per severity rank of the highest-severity node present
//     (0-24) — a correlation touching a critical finding scores higher
//     than one touching only informational ones.
//  5. +12 if any intelligence-record node carries verdict "malicious",
//     +6 for "suspicious" — external context, weighted modestly (never
//     itself enough to reach a high score alone, mirroring phase11.md's
//     own treatment of a single intelligence signal).
//
// The total is clamped to [0, 100]. Score is never described as a
// probability of attack (phase12.md §31) — see Confidence and
// DeriveSeverity for the two related-but-distinct axes.
func Score(component Graph) int {
	score := 0
	if len(component.Nodes) > 1 {
		score += 15
	}

	edgePoints := 0
	for _, e := range component.Edges {
		edgePoints += edgeConfidencePoints[e.Confidence]
	}
	if edgePoints > 40 {
		edgePoints = 40
	}
	score += edgePoints

	types := map[NodeType]bool{}
	maxSeverity := -1
	hasMalicious, hasSuspicious := false, false
	for _, n := range component.Nodes {
		types[n.Ref.Type] = true
		if sev, ok := n.Attributes["severity"].(string); ok {
			if r, ok := severityRank[sev]; ok && r > maxSeverity {
				maxSeverity = r
			}
		}
		if v, ok := n.Attributes["verdict"].(string); ok {
			switch v {
			case "malicious":
				hasMalicious = true
			case "suspicious":
				hasSuspicious = true
			}
		}
	}

	diversity := len(types) * 8
	if diversity > 24 {
		diversity = 24
	}
	score += diversity

	if maxSeverity >= 0 {
		severityPoints := maxSeverity * 6
		if severityPoints > 24 {
			severityPoints = 24
		}
		score += severityPoints
	}

	switch {
	case hasMalicious:
		score += 12
	case hasSuspicious:
		score += 6
	}

	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return score
}

// ConfidenceForScore buckets a 0-100 Score into a Confidence level
// (phase12.md §32's "calculate confidence separately from score" still
// requires one documented mapping) — an independent copy of
// internal/domain/correlation.ConfidenceForScore's identical thresholds,
// kept in this package for its own zero-domain-dependency discipline.
func ConfidenceForScore(score int) Confidence {
	switch {
	case score >= 75:
		return ConfidenceHigh
	case score >= 45:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

// DeriveSeverity derives component's overall severity from the highest
// severity rank present among its nodes, moderated by confidence
// (phase12.md §33's "do not blindly use the highest severity without
// considering confidence"): at ConfidenceLow, the raw maximum is capped
// one rank lower (never below "informational") — a low-confidence
// grouping should never present as loudly as a high-confidence one
// touching the same underlying severity. Returns "informational" if no
// node carries a recognized severity at all.
func DeriveSeverity(component Graph, confidence Confidence) string {
	maxSeverity := 0
	found := false
	for _, n := range component.Nodes {
		if sev, ok := n.Attributes["severity"].(string); ok {
			if r, ok := severityRank[sev]; ok {
				found = true
				if r > maxSeverity {
					maxSeverity = r
				}
			}
		}
	}
	if !found {
		return rankSeverity[0]
	}
	if confidence == ConfidenceLow && maxSeverity > 0 {
		maxSeverity--
	}
	return rankSeverity[maxSeverity]
}
