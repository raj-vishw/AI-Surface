package investigation

import (
	"testing"

	"github.com/google/uuid"
)

func TestIncidentCluster_Validate_Valid(t *testing.T) {
	c := IncidentCluster{TargetID: uuid.New(), Title: "Suggested cluster", Confidence: ConfidenceMedium, Status: ClusterSuggested}
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestIncidentCluster_Validate_InvalidStatus(t *testing.T) {
	c := IncidentCluster{TargetID: uuid.New(), Title: "x", Status: "bogus"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for invalid status")
	}
}

func TestClusterItem_Validate_Valid(t *testing.T) {
	i := ClusterItem{ClusterID: uuid.New(), SourceType: EntityFinding, SourceID: uuid.New()}
	if err := i.Validate(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestClusterItem_Validate_MissingSourceID(t *testing.T) {
	i := ClusterItem{ClusterID: uuid.New(), SourceType: EntityFinding}
	if err := i.Validate(); err == nil {
		t.Fatal("expected error for missing source_id")
	}
}
