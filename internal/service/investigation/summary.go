package investigation

import (
	"context"
	"time"

	"github.com/google/uuid"

	domaininvestigation "ai-surface-platform/internal/domain/investigation"
	investigationrepo "ai-surface-platform/internal/repository/investigation"
	"ai-surface-platform/internal/repository/pagination"
)

// Summary is an automatically generated, evidence-derived investigation
// overview (phase9.md §44's worked example) — also serves as the
// dashboard view model phase9.md §82 asks for (InvestigationSummary);
// every field is counted from actually-attached/actually-recorded rows,
// never invented.
type Summary struct {
	InvestigationID uuid.UUID
	Title           string
	Status          domaininvestigation.Status
	Severity        domaininvestigation.Severity
	Confidence      domaininvestigation.Confidence
	Priority        domaininvestigation.Priority
	AssignedTo      string

	AssetCount        int
	EndpointCount     int
	FindingCount      int
	OpenFindingCount  int
	EventCount        int
	RelationshipCount int
	HypothesisCount   int

	FirstObserved *time.Time
	LastObserved  *time.Time
}

// Summarize builds a Summary for investigationID purely from
// already-persisted rows (phase9.md §44: "summary must be generated from
// actual evidence — do not invent conclusions").
func (s *Service) Summarize(ctx context.Context, investigationID uuid.UUID) (Summary, error) {
	inv, err := s.investigations.GetByID(ctx, investigationID)
	if err != nil {
		return Summary{}, err
	}

	evidencePage, err := s.evidence.ListEvidence(ctx, investigationrepo.EvidenceListFilter{InvestigationID: investigationID, Pagination: pagination.Params{Limit: pagination.MaxLimit}})
	if err != nil {
		return Summary{}, err
	}
	assets := map[uuid.UUID]bool{}
	endpoints := map[uuid.UUID]bool{}
	findingCount := 0
	for _, ref := range evidencePage.Items {
		switch ref.SourceType {
		case domaininvestigation.EntityAsset:
			assets[ref.SourceID] = true
		case domaininvestigation.EntityEndpoint:
			endpoints[ref.SourceID] = true
		case domaininvestigation.EntityFinding:
			findingCount++
		}
	}

	findings, err := s.ListFindings(ctx, investigationID)
	if err != nil {
		return Summary{}, err
	}
	openCount := 0
	for _, f := range findings {
		assets[f.AssetID] = true
		if f.EndpointID != nil {
			endpoints[*f.EndpointID] = true
		}
		if f.Status.Open() {
			openCount++
		}
	}

	timelinePage, err := s.timeline.ListTimeline(ctx, investigationrepo.TimelineListFilter{InvestigationID: investigationID, Pagination: pagination.Params{Limit: pagination.MaxLimit}})
	if err != nil {
		return Summary{}, err
	}
	relPage, err := s.relationships.ListRelationships(ctx, investigationrepo.RelationshipListFilter{InvestigationID: investigationID, Pagination: pagination.Params{Limit: pagination.MaxLimit}})
	if err != nil {
		return Summary{}, err
	}
	hyps, err := s.hypotheses.ListHypotheses(ctx, investigationID)
	if err != nil {
		return Summary{}, err
	}

	return Summary{
		InvestigationID: inv.ID, Title: inv.Title, Status: inv.Status, Severity: inv.Severity,
		Confidence: inv.Confidence, Priority: inv.Priority, AssignedTo: inv.AssignedTo,
		AssetCount: len(assets), EndpointCount: len(endpoints), FindingCount: findingCount,
		OpenFindingCount: openCount, EventCount: len(timelinePage.Items), RelationshipCount: len(relPage.Items),
		HypothesisCount: len(hyps), FirstObserved: inv.FirstObservedAt, LastObserved: inv.LastObservedAt,
	}, nil
}
