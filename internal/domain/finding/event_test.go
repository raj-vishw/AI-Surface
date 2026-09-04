package finding

import (
	"testing"

	"github.com/google/uuid"
)

func TestEvent_Validate(t *testing.T) {
	e := Event{FindingID: uuid.New(), Type: EventOpened, ToStatus: StatusOpen}
	if err := e.Validate(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}

	bad := e
	bad.Type = "not_an_event"
	if err := bad.Validate(); err == nil {
		t.Fatal("expected error for invalid event type")
	}
}

func TestEvent_Validate_SuppressionEventsRequireReason(t *testing.T) {
	for _, typ := range []EventType{EventAccepted, EventMarkedFalsePositive, EventSeverityOverridden} {
		e := Event{FindingID: uuid.New(), Type: typ, ToStatus: StatusAcceptedRisk}
		if err := e.Validate(); err == nil {
			t.Fatalf("expected error for %s without reason", typ)
		}
		e.Reason = "documented, reviewed exception"
		if err := e.Validate(); err != nil {
			t.Fatalf("expected valid for %s with reason, got %v", typ, err)
		}
	}
}
