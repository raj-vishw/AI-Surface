package detection

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// DetectorError is one detector's failure during a Result — a detector
// failing must never abort the rest of the run (phase8.md §82/§83:
// "partial results").
type DetectorError struct {
	DetectorID string
	Err        error
}

func (e DetectorError) Error() string {
	return fmt.Sprintf("detector %s: %v", e.DetectorID, e.Err)
}

// Result is one Engine.Evaluate call's outcome: every finding produced by
// every detector that ran, plus a structured error for any detector that
// failed (phase8.md §83 — "10 detectors run, 1 fails: return 9 detector
// results, 1 structured detector error").
type Result struct {
	Findings []Finding
	Errors   []DetectorError
}

// Engine runs a Registry's active detectors against one Input and merges
// their output. It performs no persistence and no network request of its
// own — see internal/service/detection for both.
type Engine struct {
	registry *Registry
}

// NewEngine builds an Engine backed by registry.
func NewEngine(registry *Registry) *Engine {
	return &Engine{registry: registry}
}

// Evaluate runs every detector Registry.Active(input.Mode) returns against
// input, isolating each detector's failure (phase8.md §82), clamping any
// out-of-range Confidence a detector returns, filling in
// DetectorID/DetectorVersion/AssetID from the detector/input if a
// detector left them zero, and merging same-identity results via
// MergeFindings (phase8.md §43/§44) before returning.
func (e *Engine) Evaluate(ctx context.Context, input Input) Result {
	var result Result

	for _, d := range e.registry.Active(input.Mode) {
		if !input.Config.DetectorEnabled(d.ID()) {
			continue
		}
		if err := ctx.Err(); err != nil {
			result.Errors = append(result.Errors, DetectorError{DetectorID: d.ID(), Err: err})
			break
		}

		findings, err := d.Detect(ctx, input)
		if err != nil {
			result.Errors = append(result.Errors, DetectorError{DetectorID: d.ID(), Err: err})
			continue
		}
		for i := range findings {
			normalizeFinding(&findings[i], d, input)
		}
		result.Findings = append(result.Findings, findings...)
	}

	result.Findings = MergeFindings(result.Findings)
	return result
}

func normalizeFinding(f *Finding, d Detector, input Input) {
	if f.AssetID == uuid.Nil {
		f.AssetID = input.Asset.ID
	}
	if f.DetectorID == "" {
		f.DetectorID = d.ID()
	}
	if f.DetectorVersion == 0 {
		f.DetectorVersion = d.Version()
	}
	if f.Category == "" {
		f.Category = d.Category()
	}
	if f.Scope == "" {
		if f.EndpointID != nil {
			f.Scope = ScopeEndpoint
		} else {
			f.Scope = ScopeAsset
		}
	}
	f.Confidence = f.Confidence.Clamp()
}
