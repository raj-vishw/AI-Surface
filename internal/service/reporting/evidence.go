package reporting

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	domainreporting "ai-recon-platform/internal/domain/reporting"
	apperrors "ai-recon-platform/internal/errors"
	rept "ai-recon-platform/internal/reporting"
)

// CreateEvidencePackage implements phase14.md §45/§46/§47: builds an
// evidence package for one already-generated report, containing exactly
// the evidence that report itself cited — never a dump of unrelated
// target data. Every manifest entry is a hash of the item's own stable
// identity (internal/reporting.ItemHash), never an authentication
// mechanism (phase14.md §47).
func (s *Service) CreateEvidencePackage(ctx context.Context, reportID uuid.UUID, actor string) (domainreporting.Package, []domainreporting.Item, error) {
	if actor == "" {
		return domainreporting.Package{}, nil, apperrors.NewValidation("actor is required", nil)
	}
	report, err := s.reports.GetReportByID(ctx, reportID)
	if err != nil {
		return domainreporting.Package{}, nil, err
	}

	var envelope rept.Envelope
	if err := json.Unmarshal([]byte(report.Content), &envelope); err != nil {
		return domainreporting.Package{}, nil, fmt.Errorf("decoding report content: %w", err)
	}

	pkg := domainreporting.Package{TargetID: report.TargetID, ReportID: &report.ID, CreatedBy: actor}
	if err := pkg.Validate(); err != nil {
		return domainreporting.Package{}, nil, apperrors.NewValidation("invalid evidence package", err)
	}
	savedPkg, err := s.packages.CreatePackage(ctx, pkg)
	if err != nil {
		return domainreporting.Package{}, nil, err
	}

	items := make([]domainreporting.Item, 0, len(envelope.Refs))
	for _, r := range envelope.Refs {
		refID, err := uuid.Parse(r.ID)
		if err != nil {
			continue // a non-UUID reference (should never happen for this platform's own evidence) is skipped, never fabricated
		}
		item := domainreporting.Item{
			PackageID: savedPkg.ID, ItemType: domainreporting.EvidenceItemType(r.Type),
			ReferenceID: refID, Hash: rept.ItemHash(r.Type, r.ID, r.Timestamp), Timestamp: r.Timestamp,
		}
		if err := item.Validate(); err != nil {
			continue
		}
		items = append(items, item)
	}

	saved, err := s.items.CreateItems(ctx, items)
	if err != nil {
		return domainreporting.Package{}, nil, err
	}
	return savedPkg, saved, nil
}

// GetManifest implements phase14.md §46 — the manifest is simply the
// package's own evidence items, already carrying item id/type/hash/
// timestamp.
func (s *Service) GetManifest(ctx context.Context, packageID uuid.UUID) ([]domainreporting.Item, error) {
	return s.items.ListItemsByPackage(ctx, packageID)
}

// GetPackage returns one evidence package by id.
func (s *Service) GetPackage(ctx context.Context, id uuid.UUID) (domainreporting.Package, error) {
	return s.packages.GetPackageByID(ctx, id)
}
