package investigation

import (
	"testing"

	"github.com/google/uuid"
)

func TestNote_Validate_Valid(t *testing.T) {
	n := Note{InvestigationID: uuid.New(), AuthorID: "analyst1", Content: "Checked the git exposure finding."}
	if err := n.Validate(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestNote_Validate_MissingContent(t *testing.T) {
	n := Note{InvestigationID: uuid.New(), AuthorID: "analyst1"}
	if err := n.Validate(); err == nil {
		t.Fatal("expected error for missing content")
	}
}

func TestNote_Validate_MissingAuthor(t *testing.T) {
	n := Note{InvestigationID: uuid.New(), Content: "x"}
	if err := n.Validate(); err == nil {
		t.Fatal("expected error for missing author")
	}
}
