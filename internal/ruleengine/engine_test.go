package ruleengine

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func mustCompile(t *testing.T, def Definition) *CompiledRule {
	t.Helper()
	compiled, err := Compile(def)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return compiled
}

func TestEngine_FieldMatch(t *testing.T) {
	def := Definition{
		EventType:  EventFinding,
		Conditions: []Condition{{Field: "finding.severity", Operator: OpEquals, Value: "critical"}},
		RuleType:   TypeFieldMatch, Severity: SeverityCritical, Confidence: ConfidenceHigh, SchemaVersion: 1,
	}
	events := []Event{
		{Type: EventFinding, SourceID: uuid.New(), Timestamp: time.Now(), Fields: map[string]any{"finding.severity": "critical"}},
		{Type: EventFinding, SourceID: uuid.New(), Timestamp: time.Now(), Fields: map[string]any{"finding.severity": "low"}},
	}
	matches, err := NewEngine().Evaluate(context.Background(), mustCompile(t, def), events)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
}

func failedLoginEvent(user, ip string, at time.Time) Event {
	return Event{
		Type: EventFinding, SourceID: uuid.New(), Timestamp: at,
		Fields: map[string]any{"finding.category": "authentication", "finding.status": "open", "finding.detector_id": user + "@" + ip},
	}
}

func TestEngine_Threshold_MeetsThreshold(t *testing.T) {
	def := Definition{
		EventType:  EventFinding,
		Conditions: []Condition{{Field: "finding.category", Operator: OpEquals, Value: "authentication"}},
		RuleType:   TypeThreshold, Severity: SeverityMedium, Confidence: ConfidenceMedium, SchemaVersion: 1,
		Aggregation: &Aggregation{
			GroupBy: []string{"finding.detector_id"}, Window: 5 * time.Minute,
			Threshold: Threshold{Operator: ThresholdGreaterThanOrEqual, Value: 5},
		},
	}
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	var events []Event
	for i := 0; i < 5; i++ {
		events = append(events, failedLoginEvent("alice", "1.2.3.4", base.Add(time.Duration(i)*time.Second)))
	}

	matches, err := NewEngine().Evaluate(context.Background(), mustCompile(t, def), events)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match for 5 events meeting threshold 5, got %d", len(matches))
	}
	if len(matches[0].Events) != 5 {
		t.Fatalf("expected 5 evidence events, got %d", len(matches[0].Events))
	}
}

func TestEngine_Threshold_BelowThreshold_NoMatch(t *testing.T) {
	// phase11.md §50: 4 failed logins when threshold is 5 -> no detection.
	def := Definition{
		EventType:  EventFinding,
		Conditions: []Condition{{Field: "finding.category", Operator: OpEquals, Value: "authentication"}},
		RuleType:   TypeThreshold, Severity: SeverityMedium, Confidence: ConfidenceMedium, SchemaVersion: 1,
		Aggregation: &Aggregation{
			GroupBy: []string{"finding.detector_id"}, Window: 5 * time.Minute,
			Threshold: Threshold{Operator: ThresholdGreaterThanOrEqual, Value: 5},
		},
	}
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	var events []Event
	for i := 0; i < 4; i++ {
		events = append(events, failedLoginEvent("alice", "1.2.3.4", base.Add(time.Duration(i)*time.Second)))
	}

	matches, err := NewEngine().Evaluate(context.Background(), mustCompile(t, def), events)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no match below threshold, got %d", len(matches))
	}
}

func TestEngine_Threshold_BoundaryCase_ExactlyAtThreshold(t *testing.T) {
	def := Definition{
		EventType:  EventFinding,
		Conditions: []Condition{{Field: "finding.category", Operator: OpEquals, Value: "authentication"}},
		RuleType:   TypeThreshold, Severity: SeverityMedium, Confidence: ConfidenceMedium, SchemaVersion: 1,
		Aggregation: &Aggregation{
			GroupBy: []string{"finding.detector_id"}, Window: time.Minute,
			Threshold: Threshold{Operator: ThresholdGreaterThanOrEqual, Value: 5},
		},
	}
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	var events []Event
	for i := 0; i < 5; i++ {
		events = append(events, failedLoginEvent("alice", "1.2.3.4", base))
	}
	matches, _ := NewEngine().Evaluate(context.Background(), mustCompile(t, def), events)
	if len(matches) != 1 {
		t.Fatalf("expected exactly-at-threshold to match, got %d matches", len(matches))
	}
}

func TestEngine_Threshold_DifferentGroups_NoCrossContamination(t *testing.T) {
	def := Definition{
		EventType:  EventFinding,
		Conditions: []Condition{{Field: "finding.category", Operator: OpEquals, Value: "authentication"}},
		RuleType:   TypeThreshold, Severity: SeverityMedium, Confidence: ConfidenceMedium, SchemaVersion: 1,
		Aggregation: &Aggregation{
			GroupBy: []string{"finding.detector_id"}, Window: 5 * time.Minute,
			Threshold: Threshold{Operator: ThresholdGreaterThanOrEqual, Value: 5},
		},
	}
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	var events []Event
	for i := 0; i < 3; i++ {
		events = append(events, failedLoginEvent("alice", "1.2.3.4", base.Add(time.Duration(i)*time.Second)))
	}
	for i := 0; i < 3; i++ {
		events = append(events, failedLoginEvent("bob", "5.6.7.8", base.Add(time.Duration(i)*time.Second)))
	}
	matches, _ := NewEngine().Evaluate(context.Background(), mustCompile(t, def), events)
	if len(matches) != 0 {
		t.Fatalf("expected no match: 3+3 events split across 2 groups, neither meets threshold 5, got %d", len(matches))
	}
}

func TestEngine_Aggregation_UniqueCount(t *testing.T) {
	def := Definition{
		EventType:  EventEndpointObservation,
		Conditions: nil,
		RuleType:   TypeAggregation, Severity: SeverityLow, Confidence: ConfidenceMedium, SchemaVersion: 1,
		Aggregation: &Aggregation{
			GroupBy: []string{"event.asset_id"}, Window: time.Minute,
			Function: FunctionUniqueCount, UniqueField: "endpoint.method",
			Threshold: Threshold{Operator: ThresholdGreaterThanOrEqual, Value: 3},
		},
	}
	assetID := uuid.New()
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	events := []Event{
		{Type: EventEndpointObservation, SourceID: uuid.New(), Timestamp: base, Fields: map[string]any{"event.asset_id": assetID.String(), "endpoint.method": "GET"}},
		{Type: EventEndpointObservation, SourceID: uuid.New(), Timestamp: base, Fields: map[string]any{"event.asset_id": assetID.String(), "endpoint.method": "POST"}},
		{Type: EventEndpointObservation, SourceID: uuid.New(), Timestamp: base, Fields: map[string]any{"event.asset_id": assetID.String(), "endpoint.method": "DELETE"}},
		{Type: EventEndpointObservation, SourceID: uuid.New(), Timestamp: base, Fields: map[string]any{"event.asset_id": assetID.String(), "endpoint.method": "GET"}}, // duplicate method
	}
	matches, err := NewEngine().Evaluate(context.Background(), mustCompile(t, def), events)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match for 3 unique methods meeting threshold 3, got %d", len(matches))
	}
}

func TestEngine_Sequence_MatchesOrderedSteps(t *testing.T) {
	def := Definition{
		EventType: EventFinding, RuleType: TypeSequence, Severity: SeverityHigh, Confidence: ConfidenceHigh, SchemaVersion: 1,
		Sequence: &Sequence{
			GroupBy: []string{"finding.detector_id"},
			Window:  10 * time.Minute,
			Steps: []SequenceStep{
				{EventType: EventFinding, Conditions: []Condition{{Field: "finding.status", Operator: OpEquals, Value: "failed_login"}}},
				{EventType: EventFinding, Conditions: []Condition{{Field: "finding.status", Operator: OpEquals, Value: "successful_login"}}},
				{EventType: EventFinding, Conditions: []Condition{{Field: "finding.status", Operator: OpEquals, Value: "privileged_action"}}},
			},
		},
	}
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	mk := func(status string, offset time.Duration) Event {
		return Event{Type: EventFinding, SourceID: uuid.New(), Timestamp: base.Add(offset),
			Fields: map[string]any{"finding.status": status, "finding.detector_id": "alice"}}
	}
	events := []Event{
		mk("failed_login", 0),
		mk("successful_login", 2*time.Minute),
		mk("privileged_action", 4*time.Minute),
	}
	matches, err := NewEngine().Evaluate(context.Background(), mustCompile(t, def), events)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 sequence match, got %d", len(matches))
	}
	if len(matches[0].Events) != 3 {
		t.Fatalf("expected 3 evidence events, got %d", len(matches[0].Events))
	}
}

func TestEngine_Sequence_OutOfOrder_NoMatch(t *testing.T) {
	def := Definition{
		EventType: EventFinding, RuleType: TypeSequence, Severity: SeverityHigh, Confidence: ConfidenceHigh, SchemaVersion: 1,
		Sequence: &Sequence{
			Window: 10 * time.Minute,
			Steps: []SequenceStep{
				{EventType: EventFinding, Conditions: []Condition{{Field: "finding.status", Operator: OpEquals, Value: "failed_login"}}},
				{EventType: EventFinding, Conditions: []Condition{{Field: "finding.status", Operator: OpEquals, Value: "successful_login"}}},
			},
		},
	}
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	mk := func(status string, offset time.Duration) Event {
		return Event{Type: EventFinding, SourceID: uuid.New(), Timestamp: base.Add(offset), Fields: map[string]any{"finding.status": status}}
	}
	// successful_login BEFORE failed_login — wrong order, must not match.
	events := []Event{mk("successful_login", 0), mk("failed_login", time.Minute)}
	matches, _ := NewEngine().Evaluate(context.Background(), mustCompile(t, def), events)
	if len(matches) != 0 {
		t.Fatalf("expected no match for out-of-order events, got %d", len(matches))
	}
}

func TestEngine_Sequence_ExceedsWindow_NoMatch(t *testing.T) {
	def := Definition{
		EventType: EventFinding, RuleType: TypeSequence, Severity: SeverityHigh, Confidence: ConfidenceHigh, SchemaVersion: 1,
		Sequence: &Sequence{
			Window: 5 * time.Minute,
			Steps: []SequenceStep{
				{EventType: EventFinding, Conditions: []Condition{{Field: "finding.status", Operator: OpEquals, Value: "failed_login"}}},
				{EventType: EventFinding, Conditions: []Condition{{Field: "finding.status", Operator: OpEquals, Value: "successful_login"}}},
			},
		},
	}
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	mk := func(status string, offset time.Duration) Event {
		return Event{Type: EventFinding, SourceID: uuid.New(), Timestamp: base.Add(offset), Fields: map[string]any{"finding.status": status}}
	}
	events := []Event{mk("failed_login", 0), mk("successful_login", 10*time.Minute)}
	matches, _ := NewEngine().Evaluate(context.Background(), mustCompile(t, def), events)
	if len(matches) != 0 {
		t.Fatalf("expected no match when sequence span exceeds window, got %d", len(matches))
	}
}

func TestEngine_ContextCancelled(t *testing.T) {
	def := validFieldMatchDef()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewEngine().Evaluate(ctx, mustCompile(t, def), nil)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestEngine_Deterministic(t *testing.T) {
	def := Definition{
		EventType:  EventFinding,
		Conditions: []Condition{{Field: "finding.category", Operator: OpEquals, Value: "authentication"}},
		RuleType:   TypeThreshold, Severity: SeverityMedium, Confidence: ConfidenceMedium, SchemaVersion: 1,
		Aggregation: &Aggregation{
			GroupBy: []string{"finding.detector_id"}, Window: 5 * time.Minute,
			Threshold: Threshold{Operator: ThresholdGreaterThanOrEqual, Value: 3},
		},
	}
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	var events []Event
	for i := 0; i < 3; i++ {
		events = append(events, failedLoginEvent("alice", "1.2.3.4", base.Add(time.Duration(i)*time.Second)))
	}
	compiled := mustCompile(t, def)
	m1, _ := NewEngine().Evaluate(context.Background(), compiled, events)
	m2, _ := NewEngine().Evaluate(context.Background(), compiled, events)
	if len(m1) != len(m2) || len(m1) != 1 {
		t.Fatalf("expected identical deterministic results, got %d vs %d", len(m1), len(m2))
	}
	if m1[0].WindowStart != m2[0].WindowStart || m1[0].WindowEnd != m2[0].WindowEnd {
		t.Fatal("expected identical window boundaries across repeated evaluations")
	}
}

func TestComputeFingerprint_DeterministicAndGroupSensitive(t *testing.T) {
	ruleID := uuid.New()
	windowStart := time.Date(2026, 1, 1, 10, 3, 27, 0, time.UTC)
	window := 5 * time.Minute
	key := map[string]string{"user": "alice"}

	fp1 := ComputeFingerprint(ruleID, 1, key, windowStart, window)
	fp2 := ComputeFingerprint(ruleID, 1, key, windowStart.Add(30*time.Second), window) // same 5-minute bucket
	if fp1 != fp2 {
		t.Errorf("expected same fingerprint within the same truncated window bucket, got %q vs %q", fp1, fp2)
	}

	differentGroup := ComputeFingerprint(ruleID, 1, map[string]string{"user": "bob"}, windowStart, window)
	if fp1 == differentGroup {
		t.Error("expected different fingerprint for a different group key")
	}

	differentVersion := ComputeFingerprint(ruleID, 2, key, windowStart, window)
	if fp1 == differentVersion {
		t.Error("expected different fingerprint for a different rule version")
	}
}

func TestNormalizedHash_Deterministic(t *testing.T) {
	def := validFieldMatchDef()
	h1 := NormalizedHash(def)
	h2 := NormalizedHash(def)
	if h1 != h2 {
		t.Fatalf("expected identical hash for identical definition, got %q vs %q", h1, h2)
	}

	changed := def
	changed.Severity = SeverityCritical
	if NormalizedHash(changed) == h1 {
		t.Fatal("expected different hash for a semantically different definition")
	}
}
