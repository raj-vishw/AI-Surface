package ruleengine

import "time"

// DefaultClockSkew is the default tolerance for late-arriving events
// (phase11.md §46).
const DefaultClockSkew = 2 * time.Minute

// DefaultMaxConcurrency/DefaultEvaluationTimeout/
// DefaultHistoricalMaxRange are the safe-by-default bounds phase11.md
// §107/§108 requires — never unlimited historical evaluation, never
// unbounded concurrency.
const (
	DefaultMaxConcurrency     = 4
	DefaultEvaluationTimeout  = 30 * time.Second
	DefaultSuppressionWindow  = 15 * time.Minute
	DefaultHistoricalMaxRange = 24 * time.Hour
)

// Config configures one Engine.Evaluate run's environment (as opposed to
// the rule-specific Definition). It carries no database detail —
// internal/service/rule resolves configuration
// (internal/config.RuleEngineConfig) into this shape, the same split
// internal/investigation.Config/internal/intelligence.Config use.
type Config struct {
	// ClockSkew bounds how late an event's Timestamp may be relative to
	// when it was fetched for evaluation before internal/service/rule
	// treats it as needing re-evaluation of an already-closed window
	// (phase11.md §46/§47) — the engine package itself is pure and
	// stateless; this value exists here only so config-loading and
	// validation have one canonical home in this package. <= 0 uses
	// DefaultClockSkew.
	ClockSkew time.Duration
	// MaxConcurrency bounds how many rules internal/service/rule
	// evaluates at once (phase11.md §89/§107). <= 0 uses
	// DefaultMaxConcurrency.
	MaxConcurrency int
	// EvaluationTimeout bounds a single rule's Evaluate call
	// (phase11.md §89/§90). <= 0 uses DefaultEvaluationTimeout.
	EvaluationTimeout time.Duration
	// SuppressionWindow is the default alert-deduplication window
	// (phase11.md §34) when a suppression doesn't specify one. <= 0 uses
	// DefaultSuppressionWindow.
	SuppressionWindow time.Duration
	// HistoricalMaxRange bounds how wide a historical evaluation's
	// [from, to) range may be without an explicit --backfill opt-in
	// (phase11.md §58/§108). <= 0 uses DefaultHistoricalMaxRange.
	HistoricalMaxRange time.Duration
}

// EffectiveClockSkew returns c's effective ClockSkew.
func (c Config) EffectiveClockSkew() time.Duration {
	if c.ClockSkew <= 0 {
		return DefaultClockSkew
	}
	return c.ClockSkew
}

// EffectiveMaxConcurrency returns c's effective MaxConcurrency.
func (c Config) EffectiveMaxConcurrency() int {
	if c.MaxConcurrency <= 0 {
		return DefaultMaxConcurrency
	}
	return c.MaxConcurrency
}

// EffectiveEvaluationTimeout returns c's effective EvaluationTimeout.
func (c Config) EffectiveEvaluationTimeout() time.Duration {
	if c.EvaluationTimeout <= 0 {
		return DefaultEvaluationTimeout
	}
	return c.EvaluationTimeout
}

// EffectiveSuppressionWindow returns c's effective SuppressionWindow.
func (c Config) EffectiveSuppressionWindow() time.Duration {
	if c.SuppressionWindow <= 0 {
		return DefaultSuppressionWindow
	}
	return c.SuppressionWindow
}

// EffectiveHistoricalMaxRange returns c's effective HistoricalMaxRange.
func (c Config) EffectiveHistoricalMaxRange() time.Duration {
	if c.HistoricalMaxRange <= 0 {
		return DefaultHistoricalMaxRange
	}
	return c.HistoricalMaxRange
}
