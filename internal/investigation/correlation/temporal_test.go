package correlation

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/investigation"
)

func TestTemporalProximityRule_WithinWindow(t *testing.T) {
	now := time.Now()
	f1 := newFinding(uuid.New(), "x", now)
	f2 := newFinding(uuid.New(), "y", now.Add(2*time.Minute))

	input := investigation.Input{Findings: []investigation.FindingObservation{f1, f2}, Config: investigation.Config{TemporalWindow: 5 * time.Minute}}
	rels, err := temporalProximityRule{}.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rels) != 1 {
		t.Fatalf("expected 1 relationship, got %d", len(rels))
	}
}

func TestTemporalProximityRule_OutsideWindow(t *testing.T) {
	now := time.Now()
	f1 := newFinding(uuid.New(), "x", now)
	f2 := newFinding(uuid.New(), "y", now.Add(time.Hour))

	input := investigation.Input{Findings: []investigation.FindingObservation{f1, f2}, Config: investigation.Config{TemporalWindow: 5 * time.Minute}}
	rels, _ := temporalProximityRule{}.Evaluate(context.Background(), input)
	if len(rels) != 0 {
		t.Fatalf("expected no relationship outside the window, got %d", len(rels))
	}
}

func TestTemporalProximityRule_AloneBelowDefaultThreshold(t *testing.T) {
	// phase9.md §16: temporal proximity alone must never imply malicious
	// activity — verify its score alone never crosses the default
	// confirm threshold.
	if temporalProximityScore >= investigation.DefaultThreshold {
		t.Fatalf("temporal proximity score (%d) must stay below the default threshold (%d) on its own", temporalProximityScore, investigation.DefaultThreshold)
	}
}
