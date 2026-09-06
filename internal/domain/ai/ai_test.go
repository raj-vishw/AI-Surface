package ai

import (
	"testing"

	"github.com/google/uuid"
)

func TestSession_Validate_RequiresTargetAndUser(t *testing.T) {
	if err := (Session{}).Validate(); err == nil {
		t.Fatal("expected an error for an empty session")
	}
	s := Session{TargetID: uuid.New(), UserID: "analyst-1"}
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestMessage_Validate_RequiresRoleAndContent(t *testing.T) {
	m := Message{SessionID: uuid.New(), Role: "bogus", Content: "hi"}
	if err := m.Validate(); err == nil {
		t.Fatal("expected an error for an unrecognized role")
	}
	m.Role = RoleUser
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	m.Content = ""
	if err := m.Validate(); err == nil {
		t.Fatal("expected an error for empty content")
	}
}

func TestRequest_Validate_RequiresTaskTypeAndPromptVersion(t *testing.T) {
	r := Request{TargetID: uuid.New(), UserID: "analyst-1", TaskType: "not_a_real_task", PromptVersion: "v1", ContextHash: "abc"}
	if err := r.Validate(); err == nil {
		t.Fatal("expected an error for an unrecognized task type")
	}
	r.TaskType = TaskAlertExplanation
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestResponse_Validate_RequiresConfidenceAndNonNegativeTokens(t *testing.T) {
	r := Response{RequestID: uuid.New(), Content: "x", Model: "m", Provider: "p", Confidence: "extreme"}
	if err := r.Validate(); err == nil {
		t.Fatal("expected an error for an unrecognized confidence level")
	}
	r.Confidence = ConfidenceLow
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	r.InputTokens = -1
	if err := r.Validate(); err == nil {
		t.Fatal("expected an error for negative token count")
	}
}

func TestToolCall_Validate_RequiresResultStatus(t *testing.T) {
	c := ToolCall{TargetID: uuid.New(), UserID: "analyst-1", Tool: "get_alert", ResultStatus: "unknown_status"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected an error for an unrecognized result status")
	}
	c.ResultStatus = ToolResultSuccess
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestSession_Validate_RejectsNilInvestigationPointer(t *testing.T) {
	nilID := uuid.Nil
	s := Session{TargetID: uuid.New(), UserID: "a", InvestigationID: &nilID}
	if err := s.Validate(); err == nil {
		t.Fatal("expected an error when InvestigationID points at the nil UUID")
	}
}
