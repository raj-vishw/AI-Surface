package correlation

// Relationship names why two nodes were linked — an independent copy of
// internal/domain/correlation.Relationship (this package's own
// zero-domain-dependency vocabulary).
type Relationship string

// Recognized edge relationships.
const (
	RelationshipCaused         Relationship = "caused"
	RelationshipFollowedBy     Relationship = "followed_by"
	RelationshipOriginatedFrom Relationship = "originated_from"
	RelationshipTargeted       Relationship = "targeted"
	RelationshipAssociatedWith Relationship = "associated_with"
	RelationshipObservedOn     Relationship = "observed_on"
	RelationshipRelatedTo      Relationship = "related_to"
	RelationshipEnrichedBy     Relationship = "enriched_by"
)

// Provenance distinguishes a directly-observed link from one inferred
// from a pattern (phase12.md §10) — see
// internal/domain/correlation.Provenance's doc comment.
type Provenance string

// Recognized provenance values.
const (
	ProvenanceObserved Provenance = "observed"
	ProvenanceInferred Provenance = "inferred"
)

// Confidence is a three-level vocabulary for one edge's own reliability
// (phase12.md §9) — see internal/domain/correlation.EdgeConfidence's doc
// comment for why this package uses three levels.
type Confidence string

// Recognized confidence levels.
const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// rank orders Confidence low to high, for chain/score aggregation.
func (c Confidence) rank() int {
	switch c {
	case ConfidenceHigh:
		return 2
	case ConfidenceMedium:
		return 1
	default:
		return 0
	}
}

// Edge is one relationship a Strategy found between two Observations —
// this package's in-memory counterpart of
// internal/domain/correlation.Edge, produced entirely from
// Input with no database access of its own. Always carries an Evidence
// explanation (phase12.md §8/§39) — never an opaque, unexplained link.
type Edge struct {
	Source NodeRef
	Target NodeRef

	Relationship Relationship
	Provenance   Provenance
	Confidence   Confidence
	Evidence     string

	StrategyID      string
	StrategyVersion int
}

// Key returns the deterministic identity two Edge values share when they
// describe the same link produced by the same strategy — used by
// dedupEdges.
func (e Edge) Key() string {
	return e.Source.Key() + "|" + e.Target.Key() + "|" + string(e.Relationship) + "|" + e.StrategyID
}

// dedupEdges collapses edges sharing the same Key (a strategy firing more
// than once for the same pair, by construction or a future bug, must not
// silently double-count — mirrors internal/investigation.
// MergeRelationships exactly).
func dedupEdges(edges []Edge) []Edge {
	if len(edges) <= 1 {
		return edges
	}
	seen := make(map[string]bool, len(edges))
	out := make([]Edge, 0, len(edges))
	for _, e := range edges {
		key := e.Key()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, e)
	}
	return out
}
