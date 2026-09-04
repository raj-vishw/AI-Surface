package detection

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestEngine_Evaluate_RunsPassiveDetectors(t *testing.T) {
	r := NewRegistry()
	assetID := uuid.New()
	_ = r.Register(stubDetector{id: "a", mode: DetectorPassive, findings: []Finding{{Title: "found"}}})

	engine := NewEngine(r)
	result := engine.Evaluate(context.Background(), Input{Asset: AssetObservation{ID: assetID}, Mode: ModePassive})

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].AssetID != assetID {
		t.Errorf("expected AssetID filled in from input, got %v", result.Findings[0].AssetID)
	}
	if result.Findings[0].DetectorID != "a" {
		t.Errorf("expected DetectorID filled in, got %q", result.Findings[0].DetectorID)
	}
	if result.Findings[0].Scope != ScopeAsset {
		t.Errorf("expected default scope asset, got %q", result.Findings[0].Scope)
	}
}

func TestEngine_Evaluate_ExcludesSafeActiveUnderPassiveMode(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubDetector{id: "active-only", mode: DetectorSafeActive, findings: []Finding{{Title: "should not appear"}}})

	engine := NewEngine(r)
	result := engine.Evaluate(context.Background(), Input{Mode: ModePassive})

	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings under passive mode, got %d", len(result.Findings))
	}
}

func TestEngine_Evaluate_IsolatesDetectorFailure(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubDetector{id: "broken", mode: DetectorPassive, err: errors.New("boom")})
	_ = r.Register(stubDetector{id: "healthy", mode: DetectorPassive, findings: []Finding{{Title: "ok"}}})

	engine := NewEngine(r)
	result := engine.Evaluate(context.Background(), Input{Mode: ModePassive})

	if len(result.Findings) != 1 {
		t.Fatalf("expected the healthy detector's finding to survive, got %d findings", len(result.Findings))
	}
	if len(result.Errors) != 1 || result.Errors[0].DetectorID != "broken" {
		t.Fatalf("expected exactly one structured error for 'broken', got %#v", result.Errors)
	}
}

func TestEngine_Evaluate_ClampsOutOfRangeConfidence(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubDetector{id: "a", mode: DetectorPassive, findings: []Finding{{Title: "x", Confidence: 5.0}}})

	engine := NewEngine(r)
	result := engine.Evaluate(context.Background(), Input{Mode: ModePassive})

	if len(result.Findings) != 1 || result.Findings[0].Confidence != 1.0 {
		t.Fatalf("expected confidence clamped to 1.0, got %#v", result.Findings)
	}
}

func TestEngine_Evaluate_RespectsDetectorEnabledConfig(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubDetector{id: "a", mode: DetectorPassive, findings: []Finding{{Title: "x"}}})

	engine := NewEngine(r)
	result := engine.Evaluate(context.Background(), Input{
		Mode: ModePassive, Config: Config{Detectors: map[string]bool{"a": false}},
	})

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings with detector disabled via Config, got %d", len(result.Findings))
	}
}

func TestEngine_Evaluate_ContextCancelled(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubDetector{id: "a", mode: DetectorPassive, findings: []Finding{{Title: "x"}}})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	engine := NewEngine(r)
	result := engine.Evaluate(ctx, Input{Mode: ModePassive})

	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings once context is cancelled, got %d", len(result.Findings))
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected a structured error for the cancelled context, got %#v", result.Errors)
	}
}
