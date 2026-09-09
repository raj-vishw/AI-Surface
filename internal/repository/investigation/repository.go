// Package investigation implements persistence for the investigation
// domain model — mirroring internal/repository/finding's shape and
// conventions exactly (one PostgresRepository type implementing several
// narrow, entity-specific interfaces).
package investigation

import (
	"context"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/investigation"
	"ai-surface-platform/internal/repository/pagination"
)

// ListFilter narrows an investigation listing. Zero-valued fields are not
// applied.
type ListFilter struct {
	TargetID   uuid.UUID
	Status     investigation.Status
	Severity   investigation.Severity
	Priority   investigation.Priority
	AssignedTo string
	Pagination pagination.Params
}

// Repository persists and queries Investigation rows.
type Repository interface {
	Create(ctx context.Context, inv investigation.Investigation) (investigation.Investigation, error)
	GetByID(ctx context.Context, id uuid.UUID) (investigation.Investigation, error)
	List(ctx context.Context, filter ListFilter) (pagination.Page[investigation.Investigation], error)
	// Update persists changes to an existing investigation's mutable
	// fields, incrementing Version and refreshing UpdatedAt. It fails with
	// a errors.CategoryConflict error if expectedVersion no longer matches
	// the stored version (phase9.md §74's optimistic concurrency control)
	// — two analysts editing the same investigation never silently
	// clobber each other.
	Update(ctx context.Context, inv investigation.Investigation, expectedVersion int) (investigation.Investigation, error)
	// UpdateFirstLastObserved widens [FirstObservedAt, LastObservedAt] to
	// include observedAt if it falls outside the current range (or sets
	// both if unset) — called whenever evidence is attached, never
	// shrinking the range.
	UpdateFirstLastObserved(ctx context.Context, id uuid.UUID, observedAt time.Time) (investigation.Investigation, error)
}

// EvidenceListFilter narrows an evidence listing.
type EvidenceListFilter struct {
	InvestigationID uuid.UUID
	SourceType      investigation.EntityType
	Pagination      pagination.Params
}

// EvidenceRepository persists and queries investigation_evidence rows.
type EvidenceRepository interface {
	// AttachEvidence inserts e. If a reference to the same
	// (investigation_id, source_type, source_id) already exists, this is
	// a no-op returning the existing row and attached=false — an
	// investigation never attaches the same underlying entity twice.
	AttachEvidence(ctx context.Context, e investigation.EvidenceRef) (result investigation.EvidenceRef, attached bool, err error)
	ListEvidence(ctx context.Context, filter EvidenceListFilter) (pagination.Page[investigation.EvidenceRef], error)
}

// TimelineListFilter narrows a timeline listing.
type TimelineListFilter struct {
	InvestigationID uuid.UUID
	// NewestFirst reverses the default chronological (oldest-first)
	// ordering (phase9.md §11).
	NewestFirst bool
	Pagination  pagination.Params
}

// TimelineRepository persists and queries timeline_events rows.
type TimelineRepository interface {
	AppendEvent(ctx context.Context, e investigation.TimelineEvent) (investigation.TimelineEvent, error)
	ListTimeline(ctx context.Context, filter TimelineListFilter) (pagination.Page[investigation.TimelineEvent], error)
}

// RelationshipListFilter narrows a relationship listing.
type RelationshipListFilter struct {
	InvestigationID uuid.UUID
	Status          investigation.RelationshipStatus
	Pagination      pagination.Params
}

// RelationshipRepository persists and queries investigation_relationships
// rows.
type RelationshipRepository interface {
	// UpsertRelationship inserts r's row, or updates Score/Confidence/
	// Explanation/Signals/Status if the same (investigation_id,
	// source_type, source_id, target_type, target_id, relationship_type,
	// rule_id) tuple already exists — re-running correlation over
	// unchanged data is idempotent, never producing duplicate edges.
	UpsertRelationship(ctx context.Context, r investigation.Relationship) (result investigation.Relationship, created bool, err error)
	ListRelationships(ctx context.Context, filter RelationshipListFilter) (pagination.Page[investigation.Relationship], error)
}

// HypothesisRepository persists and queries hypotheses +
// hypothesis_evidence rows.
type HypothesisRepository interface {
	CreateHypothesis(ctx context.Context, h investigation.Hypothesis) (investigation.Hypothesis, error)
	GetHypothesis(ctx context.Context, id uuid.UUID) (investigation.Hypothesis, error)
	ListHypotheses(ctx context.Context, investigationID uuid.UUID) ([]investigation.Hypothesis, error)
	UpdateHypothesisStatus(ctx context.Context, id uuid.UUID, status investigation.HypothesisStatus, confidence investigation.Confidence) (investigation.Hypothesis, error)
	AddHypothesisEvidence(ctx context.Context, e investigation.HypothesisEvidence) (investigation.HypothesisEvidence, error)
	ListHypothesisEvidence(ctx context.Context, hypothesisID uuid.UUID) ([]investigation.HypothesisEvidence, error)
}

// NoteRepository persists and queries investigation_notes rows.
type NoteRepository interface {
	AddNote(ctx context.Context, n investigation.Note) (investigation.Note, error)
	ListNotes(ctx context.Context, investigationID uuid.UUID) ([]investigation.Note, error)
	// ApproveNote records an analyst's explicit approval of an
	// AI-generated note (phase13.md §45) — it only ever sets
	// ApprovedBy/ApprovedAt, never Content, preserving Note's own
	// immutable-content discipline (see Note's doc comment).
	ApproveNote(ctx context.Context, id uuid.UUID, approvedBy string) (investigation.Note, error)
}

// ClusterListFilter narrows an incident-cluster listing.
type ClusterListFilter struct {
	TargetID   uuid.UUID
	Status     investigation.ClusterStatus
	Pagination pagination.Params
}

// ClusterRepository persists and queries incident_clusters +
// incident_cluster_items rows.
type ClusterRepository interface {
	CreateCluster(ctx context.Context, c investigation.IncidentCluster) (investigation.IncidentCluster, error)
	GetCluster(ctx context.Context, id uuid.UUID) (investigation.IncidentCluster, error)
	ListClusters(ctx context.Context, filter ClusterListFilter) (pagination.Page[investigation.IncidentCluster], error)
	// UpdateClusterStatus transitions status — 'accepted' additionally
	// records acceptedInvestigationID (the investigation the cluster was
	// converted into); 'rejected'/'suggested' pass a nil id.
	UpdateClusterStatus(ctx context.Context, id uuid.UUID, status investigation.ClusterStatus, acceptedInvestigationID *uuid.UUID) (investigation.IncidentCluster, error)
	AddClusterItem(ctx context.Context, item investigation.ClusterItem) (investigation.ClusterItem, error)
	ListClusterItems(ctx context.Context, clusterID uuid.UUID) ([]investigation.ClusterItem, error)
}
