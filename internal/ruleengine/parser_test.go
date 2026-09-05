package ruleengine

import (
	"testing"
	"time"
)

func TestParseJSON_RoundTrip(t *testing.T) {
	def := Definition{
		EventType:  EventFinding,
		Conditions: []Condition{{Field: "finding.severity", Operator: OpEquals, Value: "high"}},
		RuleType:   TypeThreshold, Severity: SeverityHigh, Confidence: ConfidenceHigh, SchemaVersion: 1,
		Aggregation: &Aggregation{
			GroupBy: []string{"event.asset_id"}, Window: 5 * time.Minute,
			Threshold: Threshold{Operator: ThresholdGreaterThanOrEqual, Value: 5},
		},
	}
	encoded, err := EncodeJSON(def)
	if err != nil {
		t.Fatalf("EncodeJSON: %v", err)
	}
	decoded, err := ParseJSON(encoded)
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	if NormalizedHash(decoded) != NormalizedHash(def) {
		t.Fatalf("expected round-tripped definition to be semantically equivalent; original=%+v decoded=%+v", def, decoded)
	}
	if decoded.Aggregation.Window != 5*time.Minute {
		t.Errorf("expected window 5m to survive round-trip, got %s", decoded.Aggregation.Window)
	}
}

func TestParseYAML_MatchesSpecExample(t *testing.T) {
	// Adapted from phase11.md §7's own worked YAML example, using this
	// platform's actual field names.
	doc := []byte(`
event_type: finding
rule_type: threshold
severity: medium
confidence: medium
schema_version: 1
conditions:
  - field: finding.category
    operator: equals
    value: authentication
aggregation:
  group_by:
    - event.asset_id
  window:
    duration: 5m
  threshold:
    operator: greater_than_or_equal
    value: 5
`)
	def, err := ParseYAML(doc)
	if err != nil {
		t.Fatalf("ParseYAML: %v", err)
	}
	if def.EventType != EventFinding || def.RuleType != TypeThreshold {
		t.Fatalf("unexpected parsed definition: %+v", def)
	}
	if def.Aggregation.Window != 5*time.Minute {
		t.Fatalf("expected 5m window, got %s", def.Aggregation.Window)
	}
	if _, err := Compile(def); err != nil {
		t.Fatalf("expected parsed YAML rule to compile, got %v", err)
	}
}

func TestParseJSON_InvalidWindowDuration(t *testing.T) {
	doc := []byte(`{"event_type":"finding","rule_type":"threshold","severity":"medium","confidence":"medium",
		"aggregation":{"window":{"duration":"not-a-duration"},"threshold":{"operator":"greater_than_or_equal","value":5}}}`)
	if _, err := ParseJSON(doc); err == nil {
		t.Fatal("expected error for malformed window duration")
	}
}
