package reporting

import (
	"testing"

	"github.com/google/uuid"
)

func TestReport_Validate_RequiresSubjectForScopedTypes(t *testing.T) {
	r := Report{
		TargetID: uuid.New(), ReportType: TypeInvestigation, Version: 1,
		Title: "x", Content: "{}", Status: StatusGenerated, ContentHash: "h", GeneratedBy: "analyst1",
	}
	if err := r.Validate(); err == nil {
		t.Fatal("expected an error: TypeInvestigation requires SubjectID")
	}
	subject := uuid.New()
	r.SubjectID = &subject
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestReport_Validate_ExecutiveNeedsNoSubject(t *testing.T) {
	r := Report{
		TargetID: uuid.New(), ReportType: TypeExecutive, Version: 1,
		Title: "x", Content: "{}", Status: StatusGenerated, ContentHash: "h", GeneratedBy: "analyst1",
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestReport_Validate_ApprovedRequiresApprover(t *testing.T) {
	subject := uuid.New()
	r := Report{
		TargetID: uuid.New(), ReportType: TypeAsset, SubjectID: &subject, Version: 1,
		Title: "x", Content: "{}", Status: StatusApproved, ContentHash: "h", GeneratedBy: "analyst1",
	}
	if err := r.Validate(); err == nil {
		t.Fatal("expected an error: approved status requires ApprovedBy")
	}
	approver := "analyst2"
	r.ApprovedBy = &approver
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestReport_Validate_RejectsVersionZero(t *testing.T) {
	r := Report{TargetID: uuid.New(), ReportType: TypeExecutive, Title: "x", Content: "{}", Status: StatusGenerated, ContentHash: "h", GeneratedBy: "a"}
	if err := r.Validate(); err == nil {
		t.Fatal("expected an error for Version 0")
	}
}

func TestPackage_Validate(t *testing.T) {
	if err := (Package{}).Validate(); err == nil {
		t.Fatal("expected an error for an empty package")
	}
	p := Package{TargetID: uuid.New(), CreatedBy: "analyst1"}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestItem_Validate_RequiresHash(t *testing.T) {
	i := Item{PackageID: uuid.New(), ItemType: EvidenceFinding, ReferenceID: uuid.New()}
	if err := i.Validate(); err == nil {
		t.Fatal("expected an error for a missing hash")
	}
	i.Hash = "abc123"
	if err := i.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestControlEvidence_Validate(t *testing.T) {
	c := ControlEvidence{TargetID: uuid.New(), ControlID: "AC-2", EvidenceType: EvidenceFinding, ReferenceID: uuid.New(), Description: "x"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected an error for a zero CollectedAt")
	}
}
