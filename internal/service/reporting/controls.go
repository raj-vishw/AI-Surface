package reporting

import (
	"context"
	"time"

	"github.com/google/uuid"

	domainreporting "ai-surface-platform/internal/domain/reporting"
	"ai-surface-platform/internal/repository/pagination"
	reportingrepo "ai-surface-platform/internal/repository/reporting"
)

// RecordControlEvidence implements phase14.md §50 — an explicit analyst
// action; nothing in this platform infers control satisfaction
// automatically.
func (s *Service) RecordControlEvidence(ctx context.Context, c domainreporting.ControlEvidence) (domainreporting.ControlEvidence, error) {
	if err := c.Validate(); err != nil {
		return domainreporting.ControlEvidence{}, err
	}
	return s.controls.RecordControlEvidence(ctx, c)
}

// ListControlEvidence lists control evidence matching filter.
func (s *Service) ListControlEvidence(ctx context.Context, filter reportingrepo.ControlEvidenceListFilter) ([]domainreporting.ControlEvidence, error) {
	page, err := s.controls.ListControlEvidence(ctx, filter)
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

// ControlFreshness is one control's evidence-freshness summary
// (phase14.md §52): how many pieces of evidence exist and when the most
// recent one was collected. This platform defines no expiration policy,
// so evidence is never labeled "invalid" here — only its age is exposed
// for an analyst to judge (phase14.md §52's own instruction).
type ControlFreshness struct {
	ControlID     string
	EvidenceCount int
	MostRecentAt  time.Time
}

// ControlDashboard implements phase14.md §51: every control this target
// has any evidence for, with its freshness. A control an analyst expects
// but that never appears here is exactly phase14.md §51's "control with
// a gap," represented by absence, never fabricated — this function never
// invents a zero-evidence entry for a control nobody has recorded
// anything against. No compliance percentage is calculated (phase14.md
// §51's own instruction — no control-mapping framework exists to
// compute one from).
func (s *Service) ControlDashboard(ctx context.Context, targetID uuid.UUID) ([]ControlFreshness, error) {
	ids, err := s.controls.DistinctControls(ctx, targetID)
	if err != nil {
		return nil, err
	}
	out := make([]ControlFreshness, 0, len(ids))
	for _, id := range ids {
		page, err := s.controls.ListControlEvidence(ctx, reportingrepo.ControlEvidenceListFilter{
			TargetID: targetID, ControlID: id, Pagination: pagination.Params{Limit: pagination.MaxLimit},
		})
		if err != nil {
			return nil, err
		}
		f := ControlFreshness{ControlID: id, EvidenceCount: len(page.Items)}
		for _, item := range page.Items {
			if item.CollectedAt.After(f.MostRecentAt) {
				f.MostRecentAt = item.CollectedAt
			}
		}
		out = append(out, f)
	}
	return out, nil
}
