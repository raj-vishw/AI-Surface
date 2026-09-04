package correlation

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/investigation"
)

func TestChangeBasedRule_NewEndpointWithFinding(t *testing.T) {
	now := time.Now()
	epID := uuid.New()
	f := newFinding(uuid.New(), "authentication", now)
	f.EndpointID = &epID

	input := investigation.Input{
		Findings:  []investigation.FindingObservation{f},
		Endpoints: map[uuid.UUID]investigation.EndpointObservation{epID: {ID: epID, Path: "/admin", FirstSeen: now}},
		Config:    investigation.Config{TemporalWindow: 5 * time.Minute},
	}
	rels, err := changeBasedRule{}.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rels) != 1 || rels[0].TargetType != investigation.EntityEndpoint {
		t.Fatalf("unexpected relationships: %#v", rels)
	}
}

func TestChangeBasedRule_OldEndpointIgnored(t *testing.T) {
	now := time.Now()
	epID := uuid.New()
	f := newFinding(uuid.New(), "authentication", now)
	f.EndpointID = &epID

	input := investigation.Input{
		Findings:  []investigation.FindingObservation{f},
		Endpoints: map[uuid.UUID]investigation.EndpointObservation{epID: {ID: epID, FirstSeen: now.Add(-30 * 24 * time.Hour)}},
		Config:    investigation.Config{TemporalWindow: 5 * time.Minute},
	}
	rels, _ := changeBasedRule{}.Evaluate(context.Background(), input)
	if len(rels) != 0 {
		t.Fatalf("expected no relationship for a long-known endpoint, got %d", len(rels))
	}
}

func TestChangeBasedRule_NoEndpointIgnored(t *testing.T) {
	f := newFinding(uuid.New(), "x", time.Now())
	rels, _ := changeBasedRule{}.Evaluate(context.Background(), investigation.Input{Findings: []investigation.FindingObservation{f}})
	if len(rels) != 0 {
		t.Fatalf("expected no relationship without an endpoint, got %d", len(rels))
	}
}
