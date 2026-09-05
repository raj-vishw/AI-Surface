package ruleengine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

func syntheticEvents(n int) []Event {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	events := make([]Event, n)
	for i := 0; i < n; i++ {
		events[i] = Event{
			Type: EventFinding, SourceID: uuid.New(), Timestamp: base.Add(time.Duration(i) * time.Second),
			Fields: map[string]any{
				"finding.category": "authentication", "finding.status": "open",
				"finding.detector_id": fmt.Sprintf("user-%d", i%50),
			},
		}
	}
	return events
}

func benchmarkThreshold(b *testing.B, n int) {
	def := Definition{
		EventType:  EventFinding,
		Conditions: []Condition{{Field: "finding.category", Operator: OpEquals, Value: "authentication"}},
		RuleType:   TypeThreshold, Severity: SeverityMedium, Confidence: ConfidenceMedium, SchemaVersion: 1,
		Aggregation: &Aggregation{
			GroupBy: []string{"finding.detector_id"}, Window: 5 * time.Minute,
			Threshold: Threshold{Operator: ThresholdGreaterThanOrEqual, Value: 5},
		},
	}
	compiled, err := Compile(def)
	if err != nil {
		b.Fatalf("Compile: %v", err)
	}
	events := syntheticEvents(n)
	engine := NewEngine()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := engine.Evaluate(ctx, compiled, events); err != nil {
			b.Fatalf("Evaluate: %v", err)
		}
	}
}

// BenchmarkEngine_Threshold_1000Events/10000Events/100000Events cover
// phase11.md §115's required scale points.
func BenchmarkEngine_Threshold_1000Events(b *testing.B)   { benchmarkThreshold(b, 1_000) }
func BenchmarkEngine_Threshold_10000Events(b *testing.B)  { benchmarkThreshold(b, 10_000) }
func BenchmarkEngine_Threshold_100000Events(b *testing.B) { benchmarkThreshold(b, 100_000) }

func BenchmarkComputeFingerprint(b *testing.B) {
	ruleID := uuid.New()
	key := map[string]string{"user": "alice", "source_ip": "1.2.3.4"}
	windowStart := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeFingerprint(ruleID, 1, key, windowStart, 5*time.Minute)
	}
}
