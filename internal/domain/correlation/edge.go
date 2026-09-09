package correlation

import (
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// Relationship names why two nodes were linked (phase12.md §6). A closed,
// named vocabulary — never a bare "related: true".
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

var validRelationships = map[Relationship]bool{
	RelationshipCaused: true, RelationshipFollowedBy: true, RelationshipOriginatedFrom: true,
	RelationshipTargeted: true, RelationshipAssociatedWith: true, RelationshipObservedOn: true,
	RelationshipRelatedTo: true, RelationshipEnrichedBy: true,
}

// Valid reports whether r is a recognized relationship.
func (r Relationship) Valid() bool { return validRelationships[r] }

// Provenance distinguishes an edge that restates an already-persisted,
// directly-observed link (e.g. "this finding belongs to this asset" —
// simply a foreign key) from one the correlation engine inferred from a
// pattern (e.g. "these two detections occurred within the same temporal
// window") (phase12.md §10). Never collapsed into one boolean — an
// inferred edge is always visibly distinguishable from an observed one.
type Provenance string

// Recognized provenance values.
const (
	ProvenanceObserved Provenance = "observed"
	ProvenanceInferred Provenance = "inferred"
)

var validProvenance = map[Provenance]bool{ProvenanceObserved: true, ProvenanceInferred: true}

// Valid reports whether p is a recognized provenance value.
func (p Provenance) Valid() bool { return validProvenance[p] }

// EdgeConfidence is a three-level vocabulary for one edge's own
// reliability (phase12.md §9) — deliberately never treated as an observed
// fact even when high; see Correlation.Confidence's doc comment for why
// this package uses a three-level scale rather than reusing another
// domain package's confidence type.
type EdgeConfidence string

// Recognized edge confidence levels.
const (
	EdgeConfidenceLow    EdgeConfidence = "low"
	EdgeConfidenceMedium EdgeConfidence = "medium"
	EdgeConfidenceHigh   EdgeConfidence = "high"
)

var validEdgeConfidences = map[EdgeConfidence]bool{EdgeConfidenceLow: true, EdgeConfidenceMedium: true, EdgeConfidenceHigh: true}

// Valid reports whether c is a recognized edge confidence level.
func (c EdgeConfidence) Valid() bool { return validEdgeConfidences[c] }

// Edge is one relationship the correlation engine (a strategy)
// found between two Node rows (phase12.md §8). Always carries
// an Evidence explanation and a Confidence — never an opaque, unexplained
// link (mirrors internal/domain/investigation.Relationship's explainability
// discipline, extended here with the explicit Provenance axis phase9's
// model did not need).
type Edge struct {
	ID            uuid.UUID
	CorrelationID uuid.UUID

	SourceNodeID uuid.UUID
	TargetNodeID uuid.UUID

	Relationship Relationship
	Provenance   Provenance
	Confidence   EdgeConfidence

	// Evidence is a human-readable statement of why this edge exists —
	// never merely "related" (phase12.md §8/§39).
	Evidence string

	// StrategyID/StrategyVersion identify exactly which correlation
	// strategy (and revision) produced this edge (phase12.md §26) — every
	// edge is always traceable to one strategy, the same discipline
	// phase11.md §4 established for RuleID/RuleVersion on a
	// DetectionMatch.
	StrategyID      string
	StrategyVersion int

	CreatedAt time.Time
}

// Validate checks that e is internally consistent.
func (e Edge) Validate() error {
	var errs validation.Errors

	if e.CorrelationID == uuid.Nil {
		errs = errs.Add("correlation_id", "must not be empty")
	}
	if e.SourceNodeID == uuid.Nil {
		errs = errs.Add("source_node_id", "must not be empty")
	}
	if e.TargetNodeID == uuid.Nil {
		errs = errs.Add("target_node_id", "must not be empty")
	}
	if !e.Relationship.Valid() {
		errs = errs.Add("relationship", "must be a recognized relationship")
	}
	if !e.Provenance.Valid() {
		errs = errs.Add("provenance", "must be a recognized provenance value")
	}
	if !e.Confidence.Valid() {
		errs = errs.Add("confidence", "must be a recognized edge confidence level")
	}
	if e.Evidence == "" {
		errs = errs.Add("evidence", "must not be empty — an edge is never persisted without an explanation")
	}
	if e.StrategyID == "" {
		errs = errs.Add("strategy_id", "must not be empty")
	}
	if e.StrategyVersion < 1 {
		errs = errs.Add("strategy_version", "must be at least 1")
	}

	return errs.ErrOrNil()
}
