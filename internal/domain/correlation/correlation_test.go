package correlation

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func validCorrelation() Correlation {
	return Correlation{
		TargetID: uuid.New(), Title: "Suspicious activity chain on example.com",
		Status: StatusOpen, Severity: SeverityHigh, Confidence: ConfidenceMedium, Score: 60,
		Fingerprint: "fp", FirstObservedAt: time.Now(),
	}
}

func TestCorrelation_Validate(t *testing.T) {
	if err := validCorrelation().Validate(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}

	missingTitle := validCorrelation()
	missingTitle.Title = ""
	if err := missingTitle.Validate(); err == nil {
		t.Fatal("expected error for empty title")
	}

	badScore := validCorrelation()
	badScore.Score = 101
	if err := badScore.Validate(); err == nil {
		t.Fatal("expected error for out-of-range score")
	}
}

func TestCorrelation_Validate_ConfirmedRequiresActor(t *testing.T) {
	c := validCorrelation()
	c.Status = StatusConfirmed
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: confirmed status requires confirmed_by")
	}
	c.ConfirmedBy = "analyst1"
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid once confirmed_by is set, got %v", err)
	}
}

func TestCorrelation_Validate_DismissedRequiresReason(t *testing.T) {
	c := validCorrelation()
	c.Status = StatusDismissed
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: dismissed status requires a reason")
	}
	c.DismissalReason = "known automation"
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid once dismissal_reason is set, got %v", err)
	}
}

func TestConfidenceForScore(t *testing.T) {
	cases := map[int]Confidence{0: ConfidenceLow, 44: ConfidenceLow, 45: ConfidenceMedium, 74: ConfidenceMedium, 75: ConfidenceHigh, 100: ConfidenceHigh}
	for score, want := range cases {
		if got := ConfidenceForScore(score); got != want {
			t.Errorf("ConfidenceForScore(%d) = %s, want %s", score, got, want)
		}
	}
}

func TestCorrelationNode_Validate(t *testing.T) {
	n := Node{CorrelationID: uuid.New(), Type: NodeFinding, ReferenceID: uuid.New(), Role: RoleTrigger, Timestamp: time.Now()}
	if err := n.Validate(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
	n.Type = "bogus"
	if err := n.Validate(); err == nil {
		t.Fatal("expected error for unrecognized node type")
	}
}

func TestCorrelationEdge_Validate_RequiresEvidence(t *testing.T) {
	e := Edge{
		CorrelationID: uuid.New(), SourceNodeID: uuid.New(), TargetNodeID: uuid.New(),
		Relationship: RelationshipAssociatedWith, Provenance: ProvenanceInferred, Confidence: EdgeConfidenceLow,
		StrategyID: "temporal", StrategyVersion: 1,
	}
	if err := e.Validate(); err == nil {
		t.Fatal("expected error: edge requires evidence text")
	}
	e.Evidence = "Both events occurred within the configured window."
	if err := e.Validate(); err != nil {
		t.Fatalf("expected valid once evidence is set, got %v", err)
	}
}

func TestAttackChainStage_Validate_RequiresEvidence(t *testing.T) {
	s := AttackChainStage{AttackChainID: uuid.New(), Stage: StageAuthentication, Confidence: EdgeConfidenceMedium}
	if err := s.Validate(); err == nil {
		t.Fatal("expected error: stage requires at least one evidence reference")
	}
	s.Evidence = []StageEvidenceRef{{NodeType: NodeFinding, ReferenceID: uuid.New()}}
	if err := s.Validate(); err != nil {
		t.Fatalf("expected valid once evidence is set, got %v", err)
	}
}

func TestAttackChain_Validate(t *testing.T) {
	c := AttackChain{
		CorrelationID: uuid.New(), Name: "Suspicious Activity Chain",
		Confidence: ConfidenceMedium, Severity: SeverityHigh, Status: StatusOpen,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}
