package reporting

import (
	"context"

	"github.com/google/uuid"

	domainreporting "ai-surface-platform/internal/domain/reporting"
	apperrors "ai-surface-platform/internal/errors"
	reportingrepo "ai-surface-platform/internal/repository/reporting"
)

// GetReport returns one report by id.
func (s *Service) GetReport(ctx context.Context, id uuid.UUID) (domainreporting.Report, error) {
	return s.reports.GetReportByID(ctx, id)
}

// ListReports lists reports matching filter.
func (s *Service) ListReports(ctx context.Context, filter reportingrepo.ReportListFilter) ([]domainreporting.Report, error) {
	page, err := s.reports.ListReports(ctx, filter)
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

// Approve implements phase14.md §40: requires an actor and records the
// approval — the report's Content is never touched. Approving an
// already-approved report is rejected rather than silently re-recording
// a second approval over the first (an approval is a one-time,
// meaningful event, not a mutable flag).
func (s *Service) Approve(ctx context.Context, id uuid.UUID, approvedBy, notes string) (domainreporting.Report, error) {
	if approvedBy == "" {
		return domainreporting.Report{}, apperrors.NewValidation("approvedBy is required", nil)
	}
	existing, err := s.reports.GetReportByID(ctx, id)
	if err != nil {
		return domainreporting.Report{}, err
	}
	if existing.Status == domainreporting.StatusApproved {
		return domainreporting.Report{}, apperrors.NewConflict("report is already approved", nil)
	}
	return s.reports.Approve(ctx, id, approvedBy, notes)
}

// MarkReviewed transitions a report from generated/draft to reviewed —
// a distinct step before approval (phase14.md §39's lifecycle).
func (s *Service) MarkReviewed(ctx context.Context, id uuid.UUID) (domainreporting.Report, error) {
	existing, err := s.reports.GetReportByID(ctx, id)
	if err != nil {
		return domainreporting.Report{}, err
	}
	if existing.Status == domainreporting.StatusApproved {
		return domainreporting.Report{}, apperrors.NewConflict("report is already approved", nil)
	}
	return s.reports.SetStatus(ctx, id, domainreporting.StatusReviewed)
}
