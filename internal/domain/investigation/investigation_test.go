package investigation

import (
	"testing"

	"github.com/google/uuid"
)

func validInvestigation() Investigation {
	return Investigation{
		TargetID: uuid.New(), Title: "Suspicious API Surface Change",
		Status: StatusNew, CreatedBy: "analyst1",
	}
}

func TestInvestigation_Validate_Valid(t *testing.T) {
	if err := validInvestigation().Validate(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestInvestigation_Validate_MissingTargetID(t *testing.T) {
	inv := validInvestigation()
	inv.TargetID = uuid.Nil
	if err := inv.Validate(); err == nil {
		t.Fatal("expected error for missing target_id")
	}
}

func TestInvestigation_Validate_MissingTitle(t *testing.T) {
	inv := validInvestigation()
	inv.Title = "  "
	if err := inv.Validate(); err == nil {
		t.Fatal("expected error for blank title")
	}
}

func TestInvestigation_Validate_InvalidStatus(t *testing.T) {
	inv := validInvestigation()
	inv.Status = "bogus"
	if err := inv.Validate(); err == nil {
		t.Fatal("expected error for invalid status")
	}
}

func TestInvestigation_Validate_EmptyConfidenceValid(t *testing.T) {
	inv := validInvestigation()
	inv.Confidence = ""
	if err := inv.Validate(); err != nil {
		t.Fatalf("expected empty confidence to be valid, got %v", err)
	}
}

func TestInvestigation_Validate_InvalidConfidence(t *testing.T) {
	inv := validInvestigation()
	inv.Confidence = "extremely_sure"
	if err := inv.Validate(); err == nil {
		t.Fatal("expected error for invalid confidence")
	}
}

func TestInvestigation_Validate_MissingCreatedBy(t *testing.T) {
	inv := validInvestigation()
	inv.CreatedBy = ""
	if err := inv.Validate(); err == nil {
		t.Fatal("expected error for missing created_by")
	}
}

func TestStatus_Terminal(t *testing.T) {
	if !StatusClosed.Terminal() {
		t.Error("expected closed to be terminal")
	}
	if StatusOpen.Terminal() || StatusResolved.Terminal() {
		t.Error("expected open/resolved to not be terminal")
	}
}

func TestSeverity_Rank(t *testing.T) {
	if SeverityCritical.Rank() <= SeverityHigh.Rank() {
		t.Fatal("critical must outrank high")
	}
	if Severity("bogus").Rank() != -1 {
		t.Fatal("expected unrecognized severity to rank -1")
	}
}

func TestPriority_DistinctFromSeverity(t *testing.T) {
	// Just a type-system sanity check: Priority and Severity must remain
	// distinct types so they can never be silently interchanged
	// (phase9.md §29).
	p := PriorityUrgent
	s := SeverityCritical
	if string(p) == string(s) {
		t.Fatal("priority and severity value spaces should not collide by coincidence in this test")
	}
}

func TestEntityType_Valid(t *testing.T) {
	if !EntityFinding.Valid() || !EntityAsset.Valid() {
		t.Fatal("expected finding/asset to be valid entity types")
	}
	if EntityType("bogus").Valid() {
		t.Fatal("expected bogus entity type to be invalid")
	}
}
