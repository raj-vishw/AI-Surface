package correlation

import "time"

// Safe, bounded defaults (phase12.md §110/§111) — this engine never
// traverses or windows without a limit.
const (
	// DefaultTemporalWindow bounds TemporalStrategy's proximity signal
	// (phase12.md §11/§12's "support configurable windows... do not
	// allow unlimited correlation windows").
	DefaultTemporalWindow = 15 * time.Minute
	// MaxTemporalWindow is the widest window a caller may configure —
	// exceeding it is clamped, never rejected outright, so a
	// misconfigured value degrades safely (phase12.md §12).
	MaxTemporalWindow = 24 * time.Hour

	// DefaultMaxNodes/DefaultMaxEdges bound one Correlate call's output
	// graph (phase12.md §62).
	DefaultMaxNodes = 500
	DefaultMaxEdges = 1000
	// DefaultMaxDepth bounds connected-component/graph-expansion depth
	// (phase12.md §63) — see Graph.LimitDepth.
	DefaultMaxDepth = 5
	// DefaultMaxCandidates bounds how many observations one Correlate
	// call considers per target before candidate selection truncates
	// (phase12.md §64/§65) — prevents O(n^2) strategy evaluation over an
	// entire project's history.
	DefaultMaxCandidates = 2000
	// DefaultHistoricalMaxRange bounds a single Evaluate call's [from, to)
	// query range (phase12.md §64/§110's "query range" limit) — never
	// unbounded.
	DefaultHistoricalMaxRange = 24 * time.Hour
)

// Config configures one Engine.Correlate run. It carries no database
// detail — internal/service/correlation resolves configuration
// (internal/config.CorrelationConfig) into this shape, the same split
// internal/investigation.Config and internal/ruleengine.Config use.
type Config struct {
	// TemporalWindow bounds TemporalStrategy's proximity signal. <= 0
	// uses DefaultTemporalWindow; > MaxTemporalWindow is clamped to it.
	TemporalWindow time.Duration
	MaxNodes       int
	MaxEdges       int
	MaxDepth       int
	MaxCandidates  int
	// HistoricalMaxRange bounds one Evaluate call's [from, to) range. <= 0
	// uses DefaultHistoricalMaxRange.
	HistoricalMaxRange time.Duration
	// Strategies maps a strategy id to enabled/disabled — absent means
	// enabled, the same "closed set of explicit opt-outs" convention
	// internal/investigation.Config.Rules uses.
	Strategies map[string]bool
}

// EffectiveTemporalWindow returns c's effective, bounded TemporalWindow.
func (c Config) EffectiveTemporalWindow() time.Duration {
	switch {
	case c.TemporalWindow <= 0:
		return DefaultTemporalWindow
	case c.TemporalWindow > MaxTemporalWindow:
		return MaxTemporalWindow
	default:
		return c.TemporalWindow
	}
}

// EffectiveMaxNodes returns c's effective MaxNodes.
func (c Config) EffectiveMaxNodes() int {
	if c.MaxNodes <= 0 {
		return DefaultMaxNodes
	}
	return c.MaxNodes
}

// EffectiveMaxEdges returns c's effective MaxEdges.
func (c Config) EffectiveMaxEdges() int {
	if c.MaxEdges <= 0 {
		return DefaultMaxEdges
	}
	return c.MaxEdges
}

// EffectiveMaxDepth returns c's effective MaxDepth.
func (c Config) EffectiveMaxDepth() int {
	if c.MaxDepth <= 0 {
		return DefaultMaxDepth
	}
	return c.MaxDepth
}

// EffectiveMaxCandidates returns c's effective MaxCandidates.
func (c Config) EffectiveMaxCandidates() int {
	if c.MaxCandidates <= 0 {
		return DefaultMaxCandidates
	}
	return c.MaxCandidates
}

// EffectiveHistoricalMaxRange returns c's effective HistoricalMaxRange.
func (c Config) EffectiveHistoricalMaxRange() time.Duration {
	if c.HistoricalMaxRange <= 0 {
		return DefaultHistoricalMaxRange
	}
	return c.HistoricalMaxRange
}

// StrategyEnabled reports whether id is enabled under c.
func (c Config) StrategyEnabled(id string) bool {
	if c.Strategies == nil {
		return true
	}
	enabled, ok := c.Strategies[id]
	if !ok {
		return true
	}
	return enabled
}
