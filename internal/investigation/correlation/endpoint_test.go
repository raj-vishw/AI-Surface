package correlation

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/investigation"
)

func TestSameEndpointRule_LinksSharedEndpoint(t *testing.T) {
	epID := uuid.New()
	f1 := newFinding(uuid.New(), "x", time.Now())
	f1.EndpointID = &epID
	f2 := newFinding(uuid.New(), "y", time.Now())
	f2.EndpointID = &epID

	input := investigation.Input{
		Findings:  []investigation.FindingObservation{f1, f2},
		Endpoints: map[uuid.UUID]investigation.EndpointObservation{epID: {ID: epID, Path: "/api/users"}},
	}
	rels, err := sameEndpointRule{}.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rels) != 1 || rels[0].Score != sameEndpointScore {
		t.Fatalf("expected 1 relationship, got %#v", rels)
	}
}

func TestSameEndpointRule_NilEndpointsIgnored(t *testing.T) {
	f1 := newFinding(uuid.New(), "x", time.Now())
	f2 := newFinding(uuid.New(), "y", time.Now())
	rels, _ := sameEndpointRule{}.Evaluate(context.Background(), investigation.Input{Findings: []investigation.FindingObservation{f1, f2}})
	if len(rels) != 0 {
		t.Fatalf("expected no relationship when endpoints are nil, got %d", len(rels))
	}
}
