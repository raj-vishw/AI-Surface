package investigation

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestTimelineEvent_Validate_Valid(t *testing.T) {
	e := TimelineEvent{
		TargetID: uuid.New(), InvestigationID: uuid.New(), Timestamp: time.Now(),
		Type: EventFindingCreated, Title: "Finding created",
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestTimelineEvent_Validate_ZeroTimestamp(t *testing.T) {
	e := TimelineEvent{
		TargetID: uuid.New(), InvestigationID: uuid.New(),
		Type: EventFindingCreated, Title: "x",
	}
	if err := e.Validate(); err == nil {
		t.Fatal("expected error for zero timestamp — timestamps must never be fabricated as 'now'")
	}
}

func TestTimelineEvent_Validate_InvalidType(t *testing.T) {
	e := TimelineEvent{
		TargetID: uuid.New(), InvestigationID: uuid.New(), Timestamp: time.Now(),
		Type: "bogus", Title: "x",
	}
	if err := e.Validate(); err == nil {
		t.Fatal("expected error for invalid type")
	}
}

func TestEventType_CoversRequiredVocabulary(t *testing.T) {
	// phase9.md §10's explicit required list.
	required := []EventType{
		EventAssetDiscovered, EventAssetChanged, EventEndpointDiscovered, EventEndpointChanged,
		EventFindingCreated, EventFindingResolved, EventFindingReopened, EventTechnologyChanged,
		EventServiceChanged, EventScanStarted, EventScanCompleted, EventAnalystNote,
		EventIncidentCreated, EventIncidentUpdated, EventIncidentClosed,
	}
	for _, e := range required {
		if !e.Valid() {
			t.Errorf("required event type %q is not recognized as valid", e)
		}
	}
}
