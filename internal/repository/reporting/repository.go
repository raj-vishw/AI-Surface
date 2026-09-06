// Package reporting implements persistence for the reporting domain
// model (internal/domain/reporting) — mirroring internal/repository/
// correlation's shape and conventions exactly (one PostgresRepository
// type implementing several narrow, entity-specific interfaces).
package reporting

import (
	"context"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/reporting"
	"ai-recon-platform/internal/repository/pagination"
)

// ReportListFilter narrows a report listing.
type ReportListFilter struct {
	TargetID   uuid.UUID
	ReportType reporting.Type
	SubjectID  uuid.UUID
	Status     reporting.Status
	Pagination pagination.Params
}

// ReportRepository persists and queries Report rows. There is no Update
// method for report content — see Report's own doc comment; Approve is
// the sole permitted mutation.
type ReportRepository interface {
	CreateReport(ctx context.Context, r reporting.Report) (reporting.Report, error)
	GetReportByID(ctx context.Context, id uuid.UUID) (reporting.Report, error)
	ListReports(ctx context.Context, filter ReportListFilter) (pagination.Page[reporting.Report], error)
	// LatestVersion returns the highest existing Version for
	// (targetID, reportType, subjectID), or 0 if none exists yet — the
	// caller's next report is always latest+1 (phase14.md §77).
	LatestVersion(ctx context.Context, targetID uuid.UUID, reportType reporting.Type, subjectID *uuid.UUID) (int, error)
	// Approve records an analyst's explicit approval (phase14.md §40) —
	// it only ever sets ApprovedBy/ApprovedAt/ApprovalNotes/Status, never
	// Content or ContentHash.
	Approve(ctx context.Context, id uuid.UUID, approvedBy, notes string) (reporting.Report, error)
	// SetStatus transitions Status without approval (draft -> generated
	// -> reviewed) — Approve is the only path to StatusApproved.
	SetStatus(ctx context.Context, id uuid.UUID, status reporting.Status) (reporting.Report, error)
}

// PackageListFilter narrows an evidence-package listing.
type PackageListFilter struct {
	TargetID   uuid.UUID
	Pagination pagination.Params
}

// PackageRepository persists and queries evidence Package rows.
type PackageRepository interface {
	CreatePackage(ctx context.Context, p reporting.Package) (reporting.Package, error)
	GetPackageByID(ctx context.Context, id uuid.UUID) (reporting.Package, error)
	ListPackages(ctx context.Context, filter PackageListFilter) (pagination.Page[reporting.Package], error)
}

// ItemRepository persists and queries evidence Item rows.
type ItemRepository interface {
	// CreateItems inserts every item in one call — an evidence package's
	// manifest is written atomically (see internal/service/reporting's
	// use of database.Pool.WithTx).
	CreateItems(ctx context.Context, items []reporting.Item) ([]reporting.Item, error)
	ListItemsByPackage(ctx context.Context, packageID uuid.UUID) ([]reporting.Item, error)
}

// ControlEvidenceListFilter narrows a control-evidence listing.
type ControlEvidenceListFilter struct {
	TargetID   uuid.UUID
	ControlID  string
	Pagination pagination.Params
}

// ControlEvidenceRepository persists and queries ControlEvidence rows.
type ControlEvidenceRepository interface {
	RecordControlEvidence(ctx context.Context, c reporting.ControlEvidence) (reporting.ControlEvidence, error)
	ListControlEvidence(ctx context.Context, filter ControlEvidenceListFilter) (pagination.Page[reporting.ControlEvidence], error)
	// DistinctControls returns every ControlID this target has any
	// evidence for at all, sorted — the basis for phase14.md §51's
	// "controls with evidence" / implicitly "controls with gaps" (a
	// control an analyst expects but that never appears here).
	DistinctControls(ctx context.Context, targetID uuid.UUID) ([]string, error)
}
