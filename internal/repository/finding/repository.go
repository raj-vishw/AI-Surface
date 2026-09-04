// Package finding implements persistence for the finding, finding-evidence,
// and finding-event domain models — mirroring internal/repository/
// fingerprint's shape and conventions exactly (phase8.md §16/§70).
package finding

import (
	"context"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/finding"
	"ai-recon-platform/internal/repository/pagination"
)

// ListFilter narrows a finding listing. Zero-valued fields are not applied.
type ListFilter struct {
	TargetID      uuid.UUID
	AssetID       uuid.UUID
	EndpointID    uuid.UUID
	Category      finding.Category
	Severity      finding.Severity
	Status        finding.Status
	DetectorID    string
	MinConfidence float64
	ScanID        *uuid.UUID
	Pagination    pagination.Params
}

// Repository persists and queries Finding rows.
type Repository interface {
	// GetByID returns the finding with the given id, or a
	// errors.CategoryNotFound error if none exists.
	GetByID(ctx context.Context, id uuid.UUID) (finding.Finding, error)
	// List returns a page of findings matching filter, ordered by
	// (created_at, id).
	List(ctx context.Context, filter ListFilter) (pagination.Page[finding.Finding], error)
	// Upsert inserts f's row if no finding with its IdentityKey exists
	// yet, or merges a new detection run's result into the existing row
	// otherwise: LastSeen advances to the later of the two timestamps,
	// FirstSeen takes the earlier (the same MIN/MAX upsert discipline
	// every other Upsert in this project documents), DetectorVersion/
	// DetectorSeverity/Confidence/Title/Description/Remediation/
	// References/Metadata/ScanID always take the new run's values (a
	// finding's "current belief" should reflect the most recent
	// detection, mirroring fingerprint.Repository.Upsert) — but the
	// *effective* Severity is left at any existing SeverityOverridden
	// value rather than being clobbered by DetectorSeverity (phase8.md
	// §79: "never destroy detector output" applies symmetrically — an
	// override must never be silently destroyed either). Status is NOT
	// changed by Upsert; see UpdateStatus and ResolveMissing for the only
	// two ways a finding's Status changes, exactly the explicit-status-
	// change discipline every other Upsert in this project follows.
	// created reports whether a new row was inserted.
	Upsert(ctx context.Context, f finding.Finding) (result finding.Finding, created bool, err error)
	// UpdateStatus explicitly transitions a finding's lifecycle status.
	// reason is required (and stored as SuppressionReason) when status is
	// accepted_risk or false_positive; ResolvedAt is set when status
	// becomes resolved and cleared when it moves away from resolved.
	UpdateStatus(ctx context.Context, id uuid.UUID, status finding.Status, reason string) (finding.Finding, error)
	// OverrideSeverity sets a finding's effective Severity independently
	// of DetectorSeverity, recording SeverityOverridden/-Reason/-At —
	// a future Upsert will keep updating DetectorSeverity to the
	// detector's latest output, but Severity stays at the override until
	// explicitly cleared (severity = "" clears it, reverting to
	// DetectorSeverity).
	OverrideSeverity(ctx context.Context, id uuid.UUID, severity finding.Severity, reason string) (finding.Finding, error)
	// ResolveMissing marks every currently-open (open or reopened)
	// finding belonging to assetID whose id is not in stillDetected as
	// resolved — the "no longer observed" half of lifecycle tracking
	// (phase8.md §4/§64). Returns the findings that were transitioned.
	ResolveMissing(ctx context.Context, assetID uuid.UUID, stillDetected []uuid.UUID) ([]finding.Finding, error)
}

// EvidenceListFilter narrows an evidence listing.
type EvidenceListFilter struct {
	FindingID  uuid.UUID
	Pagination pagination.Params
}

// EvidenceRepository persists and queries append-only finding_evidence
// rows — named distinctly from Repository (CreateEvidence, not Create)
// because PostgresRepository implements both on one type, mirroring every
// other EvidenceRepository in this project.
type EvidenceRepository interface {
	// CreateEvidence inserts e. If an evidence row with the same
	// (finding_id, source, evidence_fingerprint) already exists, the
	// insert is a deduplicating no-op: the existing row is returned
	// unchanged and created is false.
	CreateEvidence(ctx context.Context, e finding.Evidence) (result finding.Evidence, created bool, err error)
	// ListEvidenceByFinding returns a page of evidence for
	// filter.FindingID, ordered by (created_at, id).
	ListEvidenceByFinding(ctx context.Context, filter EvidenceListFilter) (pagination.Page[finding.Evidence], error)
}

// EventListFilter narrows an event listing.
type EventListFilter struct {
	FindingID  uuid.UUID
	Pagination pagination.Params
}

// EventRepository persists and queries append-only finding_events rows —
// the lifecycle audit trail (phase8.md §71/§85).
type EventRepository interface {
	// CreateEvent inserts e. Events are never deduplicated — each call
	// records a distinct transition, even if two transitions happen to
	// carry identical field values.
	CreateEvent(ctx context.Context, e finding.Event) (finding.Event, error)
	// ListEvents returns a page of events for filter.FindingID, ordered
	// by (created_at, id) — the finding's full lifecycle history in
	// chronological order.
	ListEvents(ctx context.Context, filter EventListFilter) (pagination.Page[finding.Event], error)
	// ListEventsByScan returns every event (across every finding belonging
	// to targetID) recorded during scanID's detection run, ordered by
	// (created_at, id) — the basis for `findings diff --scan <id>`
	// (phase8.md §75): every finding_opened/finding_resolved/
	// finding_reopened event stamped with this scan_id is exactly what
	// changed during that one run, without needing to reconstruct
	// point-in-time state (see internal/service/detection.Diff). Not
	// paginated — bounded by nature to one scan's worth of transitions.
	ListEventsByScan(ctx context.Context, targetID, scanID uuid.UUID) ([]finding.Event, error)
}

// now is a seam for tests; production code always uses time.Now().UTC().
var now = func() time.Time { return time.Now().UTC() }
