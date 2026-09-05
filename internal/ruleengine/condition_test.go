package ruleengine

import (
	"testing"
	"time"
)

func TestCondition_Evaluate_UnknownField(t *testing.T) {
	c := Condition{Field: "finding.misspelled_field", Operator: OpEquals, Value: "x"}
	event := Event{Type: EventFinding, Fields: map[string]any{"finding.severity": "high"}}
	_, err := c.Evaluate(event)
	if err == nil {
		t.Fatal("expected error for unknown field, got nil (phase11.md §10: unknown fields must not be silently treated as null)")
	}
}

func TestCondition_Evaluate_TypeMismatch(t *testing.T) {
	// status_code >= "hello" is invalid (phase11.md §11's worked example,
	// adapted to this platform's own numeric field: finding.confidence).
	c := Condition{Field: "finding.confidence", Operator: OpGreaterThanOrEqual, Value: "hello"}
	event := Event{Type: EventFinding, Fields: map[string]any{"finding.confidence": 0.9}}
	_, err := c.Evaluate(event)
	if err == nil {
		t.Fatal("expected error comparing a numeric field against a non-numeric value")
	}
}

func TestCondition_Evaluate_Equals(t *testing.T) {
	c := Condition{Field: "finding.severity", Operator: OpEquals, Value: "high"}
	match := Event{Type: EventFinding, Fields: map[string]any{"finding.severity": "high"}}
	nomatch := Event{Type: EventFinding, Fields: map[string]any{"finding.severity": "low"}}

	ok, err := c.Evaluate(match)
	if err != nil || !ok {
		t.Fatalf("expected match, got ok=%v err=%v", ok, err)
	}
	ok, err = c.Evaluate(nomatch)
	if err != nil || ok {
		t.Fatalf("expected no match, got ok=%v err=%v", ok, err)
	}
}

func TestCondition_Evaluate_GreaterThanOrEqual(t *testing.T) {
	c := Condition{Field: "finding.confidence", Operator: OpGreaterThanOrEqual, Value: 0.7}
	high := Event{Type: EventFinding, Fields: map[string]any{"finding.confidence": 0.9}}
	low := Event{Type: EventFinding, Fields: map[string]any{"finding.confidence": 0.5}}

	if ok, err := c.Evaluate(high); err != nil || !ok {
		t.Fatalf("expected match for 0.9 >= 0.7, got ok=%v err=%v", ok, err)
	}
	if ok, err := c.Evaluate(low); err != nil || ok {
		t.Fatalf("expected no match for 0.5 >= 0.7, got ok=%v err=%v", ok, err)
	}
}

func TestCondition_Evaluate_ExistsNotExists(t *testing.T) {
	present := Event{Type: EventFinding, Fields: map[string]any{"finding.detector_id": "d1"}}
	absent := Event{Type: EventFinding, Fields: map[string]any{}}

	exists := Condition{Field: "finding.detector_id", Operator: OpExists}
	if ok, _ := exists.Evaluate(present); !ok {
		t.Error("expected exists=true when field present")
	}
	if ok, _ := exists.Evaluate(absent); ok {
		t.Error("expected exists=false when field absent")
	}

	notExists := Condition{Field: "finding.detector_id", Operator: OpNotExists}
	if ok, _ := notExists.Evaluate(absent); !ok {
		t.Error("expected not_exists=true when field absent")
	}
}

func TestCondition_Evaluate_InNotIn(t *testing.T) {
	c := Condition{Field: "finding.category", Operator: OpIn, Value: []any{"web", "api"}}
	web := Event{Type: EventFinding, Fields: map[string]any{"finding.category": "web"}}
	infra := Event{Type: EventFinding, Fields: map[string]any{"finding.category": "infrastructure"}}

	if ok, err := c.Evaluate(web); err != nil || !ok {
		t.Fatalf("expected web in [web, api], got ok=%v err=%v", ok, err)
	}
	if ok, err := c.Evaluate(infra); err != nil || ok {
		t.Fatalf("expected infrastructure not in [web, api], got ok=%v err=%v", ok, err)
	}
}

func TestCondition_Evaluate_ContainsStringOnly(t *testing.T) {
	c := Condition{Field: "asset.hostname", Operator: OpContains, Value: "admin"}
	match := Event{Type: EventAssetObservation, Fields: map[string]any{"asset.hostname": "admin.example.com"}}
	if ok, err := c.Evaluate(match); err != nil || !ok {
		t.Fatalf("expected contains match, got ok=%v err=%v", ok, err)
	}
}

func TestCondition_Evaluate_OperatorIncompatibleWithKind(t *testing.T) {
	// "contains" only applies to string fields.
	c := Condition{Field: "finding.confidence", Operator: OpContains, Value: "x"}
	event := Event{Type: EventFinding, Fields: map[string]any{"finding.confidence": 0.5}}
	if _, err := c.Evaluate(event); err == nil {
		t.Fatal("expected error using a string-only operator against a numeric field")
	}
}

func TestCondition_Evaluate_TimeComparison(t *testing.T) {
	now := time.Now()
	c := Condition{Field: "event.timestamp", Operator: OpGreaterThan, Value: now.Add(-time.Hour)}
	event := Event{Type: EventFinding, Fields: map[string]any{"event.timestamp": now}}
	if ok, err := c.Evaluate(event); err != nil || !ok {
		t.Fatalf("expected time comparison match, got ok=%v err=%v", ok, err)
	}
}
