package investigation

import "time"

// DefaultThreshold is the score at/above which a relationship is
// confirmed rather than left as a candidate (phase9.md §37).
const DefaultThreshold = 60

// DefaultTemporalWindow is how close two findings' FirstSeen timestamps
// must be to receive temporal-proximity signal (phase9.md §16's "findings
// within 5 minutes").
const DefaultTemporalWindow = 5 * time.Minute

// Config configures one Engine.Correlate run. It carries no database
// detail — internal/service/investigation resolves configuration
// (internal/config.InvestigationConfig) into this shape.
type Config struct {
	// Threshold is the minimum Score for a relationship to be recorded as
	// RelationshipConfirmed rather than RelationshipCandidate. <= 0 uses
	// DefaultThreshold.
	Threshold int
	// TemporalWindow bounds temporal_proximity's signal (phase9.md §16).
	// <= 0 uses DefaultTemporalWindow.
	TemporalWindow time.Duration
	// Rules maps a rule id to enabled/disabled — absent means enabled,
	// the same "closed set of explicit opt-outs" convention
	// detection.Config.Detectors uses.
	Rules map[string]bool
}

// EffectiveThreshold returns c's effective Threshold.
func (c Config) EffectiveThreshold() int {
	if c.Threshold <= 0 {
		return DefaultThreshold
	}
	return c.Threshold
}

// EffectiveTemporalWindow returns c's effective TemporalWindow.
func (c Config) EffectiveTemporalWindow() time.Duration {
	if c.TemporalWindow <= 0 {
		return DefaultTemporalWindow
	}
	return c.TemporalWindow
}

// RuleEnabled reports whether id is enabled under c.
func (c Config) RuleEnabled(id string) bool {
	if c.Rules == nil {
		return true
	}
	enabled, ok := c.Rules[id]
	if !ok {
		return true
	}
	return enabled
}
