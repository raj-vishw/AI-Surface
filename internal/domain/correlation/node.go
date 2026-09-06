package correlation

import (
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/validation"
)

// NodeType names what kind of already-persisted entity a Node
// represents (phase12.md §7). Deliberately closed and mapped onto real
// entities this platform already persists — "user"/"IP"/"domain" from
// phase12.md §6's generic vocabulary are not separately materialized here
// because this platform has no persisted User/IPRecord/DNSRecord entity
// independent of Asset (an asset's IP/hostname) or an Intelligence Record
// (a domain/IP indicator): inventing a synthetic node type for a value
// that is really an attribute of a real entity would misrepresent it as
// an independently observed thing. A shared IP/hostname/indicator value is
// instead recorded directly in Edge.Evidence's explanation text
// (phase12.md §17's "mark the relationship with source/timestamp/
// confidence" is satisfied by the edge itself). NodeInvestigation is
// included so a correlation already attached to a Phase 9 investigation
// can represent that edge explicitly.
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

var validNodeTypes = map[NodeType]bool{
	NodeFinding: true, NodeDetectionMatch: true, NodeAlert: true, NodeAsset: true,
	NodeEndpoint: true, NodeIntelligenceRecord: true, NodeInvestigation: true,
}

// Valid reports whether t is a recognized node type.
func (t NodeType) Valid() bool { return validNodeTypes[t] }

// EvidenceRole names why one node was attached to a Correlation
// (phase12.md §5's CorrelationEvidence requirement) — deliberately a
// field on Node rather than a second table duplicating the
// same (correlation_id, type, reference_id) reference: a node already IS
// the evidence reference phase12.md §5 asks for ("do not duplicate entire
// records; store references"), so adding a parallel evidence table would
// itself be the duplication phase12.md explicitly warns against.
type EvidenceRole string

// Recognized evidence roles.
const (
	RoleTrigger    EvidenceRole = "trigger"
	RoleSupporting EvidenceRole = "supporting"
)

var validRoles = map[EvidenceRole]bool{RoleTrigger: true, RoleSupporting: true}

// Valid reports whether r is a recognized evidence role.
func (r EvidenceRole) Valid() bool { return validRoles[r] }

// Node is one already-persisted entity referenced by a
// Correlation's graph (phase12.md §7) — a reference, never a copy: it
// stores only (Type, ReferenceID) plus the timestamp/attributes a
// strategy needed at evaluation time, so the underlying finding/asset/
// detection-match/... remains the single source of truth. It doubles as
// this platform's CorrelationEvidence record (see EvidenceRole).
type Node struct {
	ID            uuid.UUID
	CorrelationID uuid.UUID

	Type        NodeType
	ReferenceID uuid.UUID
	// Role names why this node was attached — every node participating in
	// at least one edge as the strategy's triggering observation is
	// RoleTrigger; every other node RoleSupporting.
	Role EvidenceRole

	// Timestamp is the underlying entity's own real observation time
	// (a finding's LastSeen, a detection match's FirstObservedAt, ...) —
	// never fabricated (phase12.md §13).
	Timestamp time.Time

	// Attributes carries the small denormalized snapshot a strategy/
	// explanation needed at evaluation time (e.g. {"asset_id": "...",
	// "severity": "high"}) — sanitized before storage exactly like
	// asset.Metadata/finding.Metadata; never a full copy of the
	// underlying row (phase12.md §5's "do not duplicate entire records").
	Attributes map[string]any

	CreatedAt time.Time
}

// Validate checks that n is internally consistent.
func (n Node) Validate() error {
	var errs validation.Errors

	if n.CorrelationID == uuid.Nil {
		errs = errs.Add("correlation_id", "must not be empty")
	}
	if !n.Type.Valid() {
		errs = errs.Add("type", "must be a recognized node type")
	}
	if n.ReferenceID == uuid.Nil {
		errs = errs.Add("reference_id", "must not be empty")
	}
	if !n.Role.Valid() {
		errs = errs.Add("role", "must be a recognized evidence role")
	}
	if n.Timestamp.IsZero() {
		errs = errs.Add("timestamp", "must not be zero")
	}

	return errs.ErrOrNil()
}
