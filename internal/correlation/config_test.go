package correlation

import (
	"testing"
	"time"
)

func TestConfig_EffectiveDefaultsAndClamping(t *testing.T) {
	var zero Config
	if zero.EffectiveTemporalWindow() != DefaultTemporalWindow {
		t.Errorf("expected default temporal window")
	}
	if zero.EffectiveMaxNodes() != DefaultMaxNodes {
		t.Errorf("expected default max nodes")
	}
	if zero.EffectiveMaxEdges() != DefaultMaxEdges {
		t.Errorf("expected default max edges")
	}
	if zero.EffectiveMaxDepth() != DefaultMaxDepth {
		t.Errorf("expected default max depth")
	}
	if zero.EffectiveMaxCandidates() != DefaultMaxCandidates {
		t.Errorf("expected default max candidates")
	}

	tooWide := Config{TemporalWindow: 48 * time.Hour}
	if got := tooWide.EffectiveTemporalWindow(); got != MaxTemporalWindow {
		t.Errorf("expected window clamped to MaxTemporalWindow, got %s", got)
	}
}

func TestConfig_StrategyEnabled(t *testing.T) {
	var zero Config
	if !zero.StrategyEnabled("anything") {
		t.Error("expected unconfigured strategy to default to enabled")
	}
	c := Config{Strategies: map[string]bool{"temporal": false}}
	if c.StrategyEnabled("temporal") {
		t.Error("expected explicitly disabled strategy to report disabled")
	}
	if !c.StrategyEnabled("network") {
		t.Error("expected an unlisted strategy to still default to enabled")
	}
}
