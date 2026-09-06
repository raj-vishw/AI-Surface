// Package correlation implements Phase 12's correlation engine: a
// self-contained set of Strategies that analyze a bounded set of
// already-persisted security observations (Phase 8 findings, Phase 11
// detection matches/alerts, Phase 10 intelligence records, Phase 2
// assets, Phase 7 endpoints) and produce an explainable Edge
// graph, split into connected components, scored, and optionally
// summarized as an attack chain. Mirroring internal/ruleengine and
// internal/investigation's split (phase8.md §1, reused for phase9.md §1
// and phase11.md §1), this package has no database dependency — it takes
// an in-memory Input built entirely from already-persisted data and
// returns in-memory Edge/Graph values; internal/service/correlation is
// the bridge that assembles Input, calls Engine.Correlate, and persists
// the result.
//
// This platform has no raw event-ingestion pipeline (see
// internal/ruleengine's package doc comment for the same point made about
// Phase 11) and no user/account/session model (it is an attack-surface
// reconnaissance platform, not a SIEM ingesting authentication logs). So
// phase12.md's SIEM-shaped vocabulary is adapted here exactly as
// phase11.md's was: "events" are normalized projections of Phase 2/7/8/10/
// 11 rows (see Observation), "identity correlation" (phase12.md §14)
// becomes correlation of this platform's own authentication-category
// findings/detections rather than user login events (see
// strategies.IdentityStrategy's doc comment), and "network correlation"
// (phase12.md §15) uses Asset.IP — never a new network scan of its own.
//
// A Correlation is never presented as a confirmed attack — every Edge
// carries an Evidence explanation, a Provenance (observed/inferred), and
// a Confidence (phase12.md §9/§10/§39), and Explain (see explain.go)
// documents its own limitations rather than asserting an unsupported
// conclusion (phase12.md §104).
package correlation

import (
	"time"

	"github.com/google/uuid"
)

// NodeType names what kind of already-persisted entity an Observation
// represents — an independent, zero-domain-dependency copy of
// internal/domain/correlation.NodeType (the same split every engine
// package keeps from its domain package).
type NodeType string

// Recognized node types.
const (
	NodeFinding            NodeType = "finding"
	NodeDetectionMatch     NodeType = "detection_match"
	NodeAlert              NodeType = "alert"
	NodeAsset              NodeType = "asset"
	NodeEndpoint           NodeType = "endpoint"
	NodeIntelligenceRecord NodeType = "intelligence_record"
	NodeInvestigation      NodeType = "investigation"
)

// Observation is the normalized slice of one already-persisted row a
// correlation strategy needs — this package's counterpart to
// internal/ruleengine.Event and internal/investigation.FindingObservation.
// Fields that don't apply to a given Type are left zero-valued; a
// strategy must check Type before relying on a type-specific field.
type Observation struct {
	Type        NodeType
	ReferenceID uuid.UUID
	TargetID    uuid.UUID
	// AssetID is uuid.Nil for observations with no direct asset
	// association (e.g. a target-scoped intelligence record).
	AssetID uuid.UUID

	// Timestamp is this observation's own real occurrence time — a
	// finding's LastSeen, a detection match's FirstObservedAt, ... —
	// never fabricated (phase12.md §13).
	Timestamp time.Time

	// Severity/Category mirror the underlying finding/detection-match's
	// own vocabulary as plain strings (this package never imports
	// internal/domain/finding or internal/domain/rule).
	Severity string
	Category string

	// IP/Hostname are populated from the observation's own asset
	// (phase12.md §15/§16) — never resolved or looked up by this engine.
	IP       string
	Hostname string

	// IndicatorType/IndicatorValue/Verdict/Confidence are populated only
	// for NodeIntelligenceRecord observations (phase12.md §17/§21).
	IndicatorType  string
	IndicatorValue string
	Verdict        string
	Confidence     string

	// RuleID/RuleCategory are populated only for NodeDetectionMatch
	// observations (phase12.md §18).
	RuleID       uuid.UUID
	RuleCategory string

	// Attributes carries anything else worth surfacing in an
	// explanation or a persisted Node snapshot.
	Attributes map[string]any
}

// NodeRef identifies one Observation/Node by its stable (Type,
// ReferenceID) identity — used wherever an Edge or a Graph needs to point
// at a node without embedding the whole Observation.
type NodeRef struct {
	Type        NodeType
	ReferenceID uuid.UUID
}

// Key returns a stable string identity for r, suitable for map keys.
func (r NodeRef) Key() string { return string(r.Type) + "|" + r.ReferenceID.String() }

// Input bundles everything one correlation pass over a target's recent
// observations consumes — built entirely from already-persisted Phase
// 2/7/8/10/11 data by internal/service/correlation's candidate-selection
// query (phase12.md §65), never assembled by a Strategy itself.
type Input struct {
	TargetID     uuid.UUID
	Observations []Observation
	Config       Config
}
