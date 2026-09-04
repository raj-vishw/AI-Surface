package investigation

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	domainfinding "ai-recon-platform/internal/domain/finding"
	domaininvestigation "ai-recon-platform/internal/domain/investigation"
	findingrepo "ai-recon-platform/internal/repository/finding"
	investigationrepo "ai-recon-platform/internal/repository/investigation"
	"ai-recon-platform/internal/repository/pagination"
)

// AttachFinding attaches an already-persisted Finding (Phase 8) to an
// investigation as evidence (phase9.md §4/§32), widening the
// investigation's observed window, recording a finding_attached timeline
// entry, and materializing the finding's own history (finding_created,
// and any finding_resolved/finding_reopened transitions it has already
// undergone — phase9.md §50: "when a finding becomes resolved, the
// investigation should preserve it... still contains historical
// evidence") onto the investigation's timeline using the finding's own
// real timestamps, never fabricated ones.
func (s *Service) AttachFinding(ctx context.Context, investigationID, findingID uuid.UUID, relation domaininvestigation.RelationType, addedBy string) (domaininvestigation.EvidenceRef, error) {
	f, err := s.findings.GetByID(ctx, findingID)
	if err != nil {
		return domaininvestigation.EvidenceRef{}, fmt.Errorf("loading finding: %w", err)
	}
	inv, err := s.investigations.GetByID(ctx, investigationID)
	if err != nil {
		return domaininvestigation.EvidenceRef{}, err
	}

	ref := domaininvestigation.EvidenceRef{
		InvestigationID: investigationID, SourceType: domaininvestigation.EntityFinding, SourceID: findingID,
		RelationType: relation, ObservedAt: f.FirstSeen, AddedAt: time.Now().UTC(), AddedBy: addedBy,
	}
	if err := ref.Validate(); err != nil {
		return domaininvestigation.EvidenceRef{}, err
	}
	result, attached, err := s.evidence.AttachEvidence(ctx, ref)
	if err != nil {
		return domaininvestigation.EvidenceRef{}, err
	}
	if !attached {
		return result, nil // already attached — idempotent, no duplicate timeline noise
	}

	s.widenObservedWindow(ctx, investigationID, f.FirstSeen)
	if !f.LastSeen.IsZero() {
		s.widenObservedWindow(ctx, investigationID, f.LastSeen)
	}
	fid := f.ID
	s.recordEvent(ctx, inv, domaininvestigation.EventFindingAttached, "Finding attached: "+f.Title, "", addedBy, &fid)
	s.materializeFindingHistory(ctx, inv, f)

	return result, nil
}

// materializeFindingHistory projects a finding's own real history onto
// the investigation timeline (phase9.md §11's "never fabricate
// timestamps" — every event below uses the finding's/event's own
// timestamp, not time.Now()).
func (s *Service) materializeFindingHistory(ctx context.Context, inv domaininvestigation.Investigation, f domainfinding.Finding) {
	fid := f.ID
	created := domaininvestigation.TimelineEvent{
		TargetID: inv.TargetID, InvestigationID: inv.ID, Timestamp: f.FirstSeen,
		Type: domaininvestigation.EventFindingCreated, SourceType: domaininvestigation.EntityFinding, SourceID: &fid,
		Title: f.Title, Description: f.Description, Severity: string(f.Severity), Actor: "system",
		Metadata: map[string]any{"detector_id": f.DetectorID},
	}
	if err := created.Validate(); err == nil {
		if _, err := s.timeline.AppendEvent(ctx, created); err != nil {
			s.logger.Error("investigation_timeline_materialize_failed", "investigation_id", inv.ID, "finding_id", f.ID, "error", err)
		}
	}

	page, err := s.findingEvents.ListEvents(ctx, findingrepo.EventListFilter{FindingID: f.ID, Pagination: pagination.Params{Limit: pagination.MaxLimit}})
	if err != nil {
		s.logger.Error("investigation_finding_history_load_failed", "investigation_id", inv.ID, "finding_id", f.ID, "error", err)
		return
	}
	for _, ev := range page.Items {
		eventType, title := mapFindingEvent(ev, f)
		if eventType == "" {
			continue
		}
		e := domaininvestigation.TimelineEvent{
			TargetID: inv.TargetID, InvestigationID: inv.ID, Timestamp: ev.DetectedAt,
			Type: eventType, SourceType: domaininvestigation.EntityFinding, SourceID: &fid,
			Title: title, Severity: string(ev.Severity), Actor: "system",
		}
		if err := e.Validate(); err != nil {
			continue
		}
		if _, err := s.timeline.AppendEvent(ctx, e); err != nil {
			s.logger.Error("investigation_timeline_materialize_failed", "investigation_id", inv.ID, "finding_id", f.ID, "error", err)
		}
	}
}

func mapFindingEvent(ev domainfinding.Event, f domainfinding.Finding) (domaininvestigation.EventType, string) {
	switch ev.Type {
	case domainfinding.EventResolved:
		return domaininvestigation.EventFindingResolved, "Finding resolved: " + f.Title
	case domainfinding.EventReopened:
		return domaininvestigation.EventFindingReopened, "Finding reopened: " + f.Title
	default:
		return "", ""
	}
}

// AttachEvidence attaches an already-persisted asset/endpoint/scan
// reference to an investigation (phase9.md §32) — the generic sibling of
// AttachFinding for non-finding evidence.
func (s *Service) AttachEvidence(ctx context.Context, investigationID uuid.UUID, sourceType domaininvestigation.EntityType, sourceID uuid.UUID, addedBy string) (domaininvestigation.EvidenceRef, error) {
	observedAt, err := s.observedAtFor(ctx, sourceType, sourceID)
	if err != nil {
		return domaininvestigation.EvidenceRef{}, err
	}
	inv, err := s.investigations.GetByID(ctx, investigationID)
	if err != nil {
		return domaininvestigation.EvidenceRef{}, err
	}

	ref := domaininvestigation.EvidenceRef{
		InvestigationID: investigationID, SourceType: sourceType, SourceID: sourceID,
		ObservedAt: observedAt, AddedAt: time.Now().UTC(), AddedBy: addedBy,
	}
	if err := ref.Validate(); err != nil {
		return domaininvestigation.EvidenceRef{}, err
	}
	result, attached, err := s.evidence.AttachEvidence(ctx, ref)
	if err != nil {
		return domaininvestigation.EvidenceRef{}, err
	}
	if attached {
		s.widenObservedWindow(ctx, investigationID, observedAt)
		s.recordEvent(ctx, inv, domaininvestigation.EventEvidenceAttached, fmt.Sprintf("%s attached as evidence.", sourceType), "", addedBy, &sourceID)
	}
	return result, nil
}

func (s *Service) observedAtFor(ctx context.Context, sourceType domaininvestigation.EntityType, sourceID uuid.UUID) (time.Time, error) {
	switch sourceType {
	case domaininvestigation.EntityAsset:
		a, err := s.assets.GetByID(ctx, sourceID)
		if err != nil {
			return time.Time{}, fmt.Errorf("loading asset: %w", err)
		}
		return a.FirstSeen, nil
	case domaininvestigation.EntityEndpoint:
		e, err := s.endpoints.GetByID(ctx, sourceID)
		if err != nil {
			return time.Time{}, fmt.Errorf("loading endpoint: %w", err)
		}
		return e.FirstSeen, nil
	case domaininvestigation.EntityFinding:
		f, err := s.findings.GetByID(ctx, sourceID)
		if err != nil {
			return time.Time{}, fmt.Errorf("loading finding: %w", err)
		}
		return f.FirstSeen, nil
	default:
		return time.Now().UTC(), nil
	}
}

// ListEvidence returns a page of an investigation's attached evidence.
func (s *Service) ListEvidence(ctx context.Context, investigationID uuid.UUID, sourceType domaininvestigation.EntityType, p pagination.Params) (pagination.Page[domaininvestigation.EvidenceRef], error) {
	return s.evidence.ListEvidence(ctx, investigationrepo.EvidenceListFilter{InvestigationID: investigationID, SourceType: sourceType, Pagination: p})
}

// ListFindings returns every Finding (Phase 8, fully hydrated — not just
// the reference) attached to an investigation (phase9.md §51's "active
// vs. historical evidence" distinction: a finding's own current Status
// tells the caller which it is; resolved findings remain in this list,
// never removed — phase9.md §50).
func (s *Service) ListFindings(ctx context.Context, investigationID uuid.UUID) ([]domainfinding.Finding, error) {
	page, err := s.ListEvidence(ctx, investigationID, domaininvestigation.EntityFinding, pagination.Params{Limit: pagination.MaxLimit})
	if err != nil {
		return nil, err
	}
	out := make([]domainfinding.Finding, 0, len(page.Items))
	for _, ref := range page.Items {
		f, err := s.findings.GetByID(ctx, ref.SourceID)
		if err != nil {
			s.logger.Error("investigation_finding_lookup_failed", "investigation_id", investigationID, "finding_id", ref.SourceID, "error", err)
			continue
		}
		out = append(out, f)
	}
	return out, nil
}
