// Package tools implements Phase 13's read-only AI tools (phase13.md
// §28) — one thin wrapper per internal/ai.DataSource method, each
// independently registerable and independently testable against a fake
// DataSource, mirroring internal/correlation/strategies' package shape
// exactly. Every tool here is structurally read-only: none has any way to
// write, block, scan, or execute anything (phase13.md §31) — the
// DataSource interface it is built against has no mutating method at all.
package tools

import "ai-surface-platform/internal/ai"

// RegisterAll registers every built-in tool against ds into r.
func RegisterAll(r *ai.ToolRegistry, ds ai.DataSource) error {
	all := []ai.Tool{
		NewGetInvestigation(ds),
		NewGetAlert(ds),
		NewGetDetection(ds),
		NewGetCorrelation(ds),
		NewGetTimeline(ds),
		NewGetFindings(ds),
		NewGetAssets(ds),
		NewGetIntelligence(ds),
		NewGetRisk(ds),
	}
	for _, t := range all {
		if err := r.Register(t); err != nil {
			return err
		}
	}
	return nil
}
