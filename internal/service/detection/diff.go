package detection

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"ai-surface-platform/internal/detection"
	domainfinding "ai-surface-platform/internal/domain/finding"
	findingrepo "ai-surface-platform/internal/repository/finding"
	"ai-surface-platform/internal/repository/pagination"
)

// DiffEntry is one finding's classification within a specific scan
// (phase8.md §75).
type DiffEntry struct {
	FindingID uuid.UUID
	Title     string
	Severity  domainfinding.Severity
	Type      detection.ChangeType
}

// Diff returns every lifecycle change finding_events recorded for scanID
// within targetID (phase8.md §75's RESOLVED/PERSISTING/NEW breakdown) —
// reconstructed entirely from the append-only event trail a prior Run
// call already wrote, never by re-running detection.
func (s *Service) Diff(ctx context.Context, targetID, scanID uuid.UUID) ([]DiffEntry, error) {
	events, err := s.events.ListEventsByScan(ctx, targetID, scanID)
	if err != nil {
		return nil, fmt.Errorf("loading finding events for scan %s: %w", scanID, err)
	}

	entries := make([]DiffEntry, 0, len(events))
	for _, e := range events {
		changeType := changeTypeForEvent(e.Type)
		if changeType == "" {
			continue
		}
		f, err := s.findings.GetByID(ctx, e.FindingID)
		if err != nil {
			continue
		}
		entries = append(entries, DiffEntry{FindingID: f.ID, Title: f.Title, Severity: f.Severity, Type: changeType})
	}
	return entries, nil
}

func changeTypeForEvent(t domainfinding.EventType) detection.ChangeType {
	switch t {
	case domainfinding.EventOpened:
		return detection.ChangeNew
	case domainfinding.EventReopened:
		return detection.ChangeReopened
	case domainfinding.EventResolved:
		return detection.ChangeResolved
	default:
		return ""
	}
}

// GetByID returns a persisted finding.
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (domainfinding.Finding, error) {
	return s.findings.GetByID(ctx, id)
}

// List returns a page of persisted findings matching filter.
func (s *Service) List(ctx context.Context, filter findingrepo.ListFilter) (pagination.Page[domainfinding.Finding], error) {
	return s.findings.List(ctx, filter)
}

// UpdateStatus explicitly transitions a finding's lifecycle status
// (phase8.md §77/§78 — accepted_risk/false_positive both require reason).
func (s *Service) UpdateStatus(ctx context.Context, id uuid.UUID, status domainfinding.Status, reason string) (domainfinding.Finding, error) {
	return s.findings.UpdateStatus(ctx, id, status, reason)
}

// OverrideSeverity sets a finding's effective severity independently of
// its detector-computed one (phase8.md §79).
func (s *Service) OverrideSeverity(ctx context.Context, id uuid.UUID, severity domainfinding.Severity, reason string) (domainfinding.Finding, error) {
	result, err := s.findings.OverrideSeverity(ctx, id, severity, reason)
	if err != nil {
		return domainfinding.Finding{}, err
	}
	s.recordEvent(ctx, id, nil, domainfinding.EventSeverityOverridden, "", result.Status, result.Severity, result.Confidence, reason)
	return result, nil
}

// ListEvidence returns a page of evidence for a finding.
func (s *Service) ListEvidence(ctx context.Context, filter findingrepo.EvidenceListFilter) (pagination.Page[domainfinding.Evidence], error) {
	return s.evidence.ListEvidenceByFinding(ctx, filter)
}

// ListEvents returns a page of lifecycle events for a finding.
func (s *Service) ListEvents(ctx context.Context, filter findingrepo.EventListFilter) (pagination.Page[domainfinding.Event], error) {
	return s.events.ListEvents(ctx, filter)
}
