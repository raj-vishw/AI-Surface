package investigation

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestEvidenceRef_Validate_Valid(t *testing.T) {
	e := EvidenceRef{
		InvestigationID: uuid.New(), SourceType: EntityFinding, SourceID: uuid.New(),
		RelationType: RelationCorrelated, AddedBy: "analyst1", ObservedAt: time.Now(), AddedAt: time.Now(),
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestEvidenceRef_Validate_RelationTypeOnlyForFinding(t *testing.T) {
	e := EvidenceRef{
		InvestigationID: uuid.New(), SourceType: EntityAsset, SourceID: uuid.New(),
		RelationType: RelationConfirmed, AddedBy: "analyst1",
	}
	if err := e.Validate(); err == nil {
		t.Fatal("expected error: relation_type set on a non-finding reference")
	}
}

func TestEvidenceRef_Validate_MissingAddedBy(t *testing.T) {
	e := EvidenceRef{InvestigationID: uuid.New(), SourceType: EntityAsset, SourceID: uuid.New()}
	if err := e.Validate(); err == nil {
		t.Fatal("expected error for missing added_by")
	}
}

func TestEvidenceRef_Validate_InvalidSourceType(t *testing.T) {
	e := EvidenceRef{InvestigationID: uuid.New(), SourceType: "bogus", SourceID: uuid.New(), AddedBy: "a"}
	if err := e.Validate(); err == nil {
		t.Fatal("expected error for invalid source_type")
	}
}
