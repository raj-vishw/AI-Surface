package investigation

import (
	"testing"

	"github.com/google/uuid"
)

func validRelationship() Relationship {
	return Relationship{
		InvestigationID: uuid.New(), SourceType: EntityFinding, SourceID: uuid.New(),
		TargetType: EntityFinding, TargetID: uuid.New(), Type: RelationshipSameAsset,
		Status: RelationshipCandidate, Confidence: ConfidenceMedium,
		Explanation: "Both findings affect the same asset.", RuleID: "same_asset_findings",
	}
}

func TestRelationship_Validate_Valid(t *testing.T) {
	if err := validRelationship().Validate(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestRelationship_Validate_MissingExplanation(t *testing.T) {
	r := validRelationship()
	r.Explanation = ""
	if err := r.Validate(); err == nil {
		t.Fatal("expected error: a relationship must always carry an explanation (phase9.md §35)")
	}
}

func TestRelationship_Validate_MissingRuleID(t *testing.T) {
	r := validRelationship()
	r.RuleID = ""
	if err := r.Validate(); err == nil {
		t.Fatal("expected error for missing rule_id")
	}
}

func TestRelationship_Validate_InvalidType(t *testing.T) {
	r := validRelationship()
	r.Type = "bogus"
	if err := r.Validate(); err == nil {
		t.Fatal("expected error for invalid relationship type")
	}
}

func TestRelationship_Validate_InvalidStatus(t *testing.T) {
	r := validRelationship()
	r.Status = "bogus"
	if err := r.Validate(); err == nil {
		t.Fatal("expected error for invalid status")
	}
}
