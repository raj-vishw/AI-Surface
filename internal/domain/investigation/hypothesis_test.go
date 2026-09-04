package investigation

import (
	"testing"

	"github.com/google/uuid"
)

func TestHypothesis_Validate_Valid(t *testing.T) {
	h := Hypothesis{
		InvestigationID: uuid.New(), Title: "Admin endpoint linked to recent deployment",
		Status: HypothesisProposed, Confidence: ConfidenceLow, CreatedBy: "analyst1",
	}
	if err := h.Validate(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestHypothesis_Validate_InvalidStatus(t *testing.T) {
	h := Hypothesis{InvestigationID: uuid.New(), Title: "x", Status: "bogus", CreatedBy: "a"}
	if err := h.Validate(); err == nil {
		t.Fatal("expected error for invalid status")
	}
}

func TestHypothesisEvidence_Validate_Valid(t *testing.T) {
	e := HypothesisEvidence{
		HypothesisID: uuid.New(), SourceType: EntityEndpoint, SourceID: uuid.New(),
		Description: "endpoint first seen at 10:05",
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestHypothesisEvidence_Validate_MissingDescription(t *testing.T) {
	e := HypothesisEvidence{HypothesisID: uuid.New(), SourceType: EntityEndpoint, SourceID: uuid.New()}
	if err := e.Validate(); err == nil {
		t.Fatal("expected error: hypothesis evidence must never be bare speculation (phase9.md §25)")
	}
}
