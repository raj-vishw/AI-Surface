package ai

import (
	"testing"

	"github.com/google/uuid"
)

func TestResolveOrCheckTarget_FillsInWhenZero(t *testing.T) {
	targetID := uuid.New()
	req := TaskRequest{}
	if err := resolveOrCheckTarget(&req, targetID.String()); err != nil {
		t.Fatalf("resolveOrCheckTarget: %v", err)
	}
	if req.TargetID != targetID {
		t.Errorf("req.TargetID = %s, want %s", req.TargetID, targetID)
	}
}

func TestResolveOrCheckTarget_RejectsMismatch(t *testing.T) {
	req := TaskRequest{TargetID: uuid.New()}
	otherTarget := uuid.New()
	if err := resolveOrCheckTarget(&req, otherTarget.String()); err == nil {
		t.Fatal("expected an error when the context's target does not match the request's own target")
	}
}

func TestResolveOrCheckTarget_AcceptsMatch(t *testing.T) {
	id := uuid.New()
	req := TaskRequest{TargetID: id}
	if err := resolveOrCheckTarget(&req, id.String()); err != nil {
		t.Fatalf("resolveOrCheckTarget: %v", err)
	}
}
