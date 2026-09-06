package reporting

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"ai-recon-platform/internal/analytics"
	domainreporting "ai-recon-platform/internal/domain/reporting"
	apperrors "ai-recon-platform/internal/errors"
	rept "ai-recon-platform/internal/reporting"
)

// GenerateRequest is one caller's ask to build a report (phase14.md
// §31/§32). SubjectID is required for investigation/asset/correlation
// reports and ignored otherwise — see domainreporting.Type.
// RequiresSubject.
type GenerateRequest struct {
	TargetID   uuid.UUID
	ReportType domainreporting.Type
	SubjectID  *uuid.UUID
	Range      analytics.TimeRange // used only by target-wide report types
	Actor      string
}

// Generate implements phase14.md §31: builds the requested report type's
// sections, validates every citation against the report's own evidence
// list (never allowing a fabricated reference — phase14.md §92),
// computes its content hash, assigns it the next sequential version for
// its (target, type, subject) identity (phase14.md §77 — never
// overwriting an earlier version), and persists it with an initial
// status of "generated" (fully deterministic reports — see the package
// doc comment's Known Limitations on why no report here yet embeds a
// Phase 13 AI-generated section, which would instead start "draft" per
// phase14.md §39).
func (s *Service) Generate(ctx context.Context, req GenerateRequest) (domainreporting.Report, error) {
	if req.Actor == "" {
		return domainreporting.Report{}, apperrors.NewValidation("actor is required", nil)
	}
	if !req.ReportType.Valid() {
		return domainreporting.Report{}, apperrors.NewValidation(fmt.Sprintf("unrecognized report type %q", req.ReportType), nil)
	}
	if req.ReportType.RequiresSubject() && (req.SubjectID == nil || *req.SubjectID == uuid.Nil) {
		return domainreporting.Report{}, apperrors.NewValidation(fmt.Sprintf("report type %q requires a subject id", req.ReportType), nil)
	}

	result, err := s.build(ctx, req)
	if err != nil {
		return domainreporting.Report{}, err
	}

	redacted := rept.RedactSections(result.Sections)
	cleaned, removed := rept.ValidateSections(redacted, result.Refs)
	if len(removed) > 0 {
		s.logger.Warn("report_citation_stripped", "report_type", req.ReportType, "removed", removed)
	}

	latest, err := s.reports.LatestVersion(ctx, req.TargetID, req.ReportType, req.SubjectID)
	if err != nil {
		return domainreporting.Report{}, err
	}
	version := latest + 1

	envelope := rept.Envelope{
		Metadata: rept.Metadata{
			ReportType: string(req.ReportType), TargetID: req.TargetID.String(),
			GeneratedBy: req.Actor, Status: string(domainreporting.StatusGenerated),
		},
		ReportVersion:      version,
		Data:               cleaned,
		EvidenceReferences: cleaned.AllCitations(),
		Refs:               result.Refs,
	}
	if req.SubjectID != nil {
		envelope.Metadata.SubjectID = req.SubjectID.String()
	}
	contentJSON, err := json.Marshal(envelope)
	if err != nil {
		return domainreporting.Report{}, apperrors.NewInternal("encoding report content", err)
	}
	content := string(contentJSON)

	report := domainreporting.Report{
		TargetID: req.TargetID, ReportType: req.ReportType, SubjectID: req.SubjectID,
		Version: version, Title: result.Title, Content: content,
		Status: domainreporting.StatusGenerated, ContentHash: rept.ContentHash(content),
		GeneratedBy: req.Actor,
	}
	if err := report.Validate(); err != nil {
		return domainreporting.Report{}, apperrors.NewValidation("invalid report", err)
	}

	return s.reports.CreateReport(ctx, report)
}

func (s *Service) build(ctx context.Context, req GenerateRequest) (buildResult, error) {
	switch req.ReportType {
	case domainreporting.TypeInvestigation:
		return s.buildInvestigationReport(ctx, req.TargetID, *req.SubjectID)
	case domainreporting.TypeAsset:
		return s.buildAssetReport(ctx, req.TargetID, *req.SubjectID)
	case domainreporting.TypeCorrelation:
		return s.buildCorrelationReport(ctx, req.TargetID, *req.SubjectID)
	case domainreporting.TypeDetection:
		return s.buildDetectionReport(ctx, req.TargetID, req.Range)
	case domainreporting.TypeAttackSurface:
		return s.buildAttackSurfaceReport(ctx, req.TargetID, req.Range)
	case domainreporting.TypeExecutive:
		return s.buildExecutiveReport(ctx, req.TargetID, req.Range)
	case domainreporting.TypeAudit:
		return s.buildAuditReport(ctx, req.TargetID, req.Range)
	default:
		return buildResult{}, apperrors.NewValidation(fmt.Sprintf("report type %q is not yet implemented", req.ReportType), nil)
	}
}
