package ruleengine

import "time"

// Type names which of the four supported rule languages a Definition
// uses (phase11.md §6) — an independent copy of
// internal/domain/rule.Type's vocabulary (see event.go's note on why
// this package duplicates rather than imports the domain package's
// enums).
type Type string

// Recognized rule types.
const (
	TypeFieldMatch  Type = "field_match"
	TypeThreshold   Type = "threshold"
	TypeSequence    Type = "sequence"
	TypeAggregation Type = "aggregation"
)

// Severity mirrors internal/domain/rule's vocabulary — an independent
// copy, same zero-domain-dependency discipline every engine package in
// this project follows. Confidence below is the same kind of copy.
type Severity string

// Recognized severities.
const (
	SeverityInformational Severity = "informational"
	SeverityLow           Severity = "low"
	SeverityMedium        Severity = "medium"
	SeverityHigh          Severity = "high"
	SeverityCritical      Severity = "critical"
)

// Confidence levels.
type Confidence string

// Recognized confidence levels.
const (
	ConfidenceVeryLow  Confidence = "very_low"
	ConfidenceLow      Confidence = "low"
	ConfidenceMedium   Confidence = "medium"
	ConfidenceHigh     Confidence = "high"
	ConfidenceVeryHigh Confidence = "very_high"
)

// AggregationFunction names the one of two supported aggregation
// functions (phase11.md §42) — deliberately not an arbitrary expression
// language.
type AggregationFunction string

// Recognized aggregation functions.
const (
	FunctionCount       AggregationFunction = "count"
	FunctionUniqueCount AggregationFunction = "unique_count"
)

// ThresholdOperator names the comparison a threshold/aggregation count
// is checked with — a small closed subset of Operator (only the ordered
// + equality comparisons make sense against a count).
type ThresholdOperator string

// Recognized threshold operators.
const (
	ThresholdGreaterThan        ThresholdOperator = "greater_than"
	ThresholdGreaterThanOrEqual ThresholdOperator = "greater_than_or_equal"
	ThresholdLessThan           ThresholdOperator = "less_than"
	ThresholdLessThanOrEqual    ThresholdOperator = "less_than_or_equal"
	ThresholdEquals             ThresholdOperator = "equals"
)

// Satisfies reports whether count satisfies this threshold against
// value.
func (o ThresholdOperator) Satisfies(count int, value float64) bool {
	c := float64(count)
	switch o {
	case ThresholdGreaterThan:
		return c > value
	case ThresholdGreaterThanOrEqual:
		return c >= value
	case ThresholdLessThan:
		return c < value
	case ThresholdLessThanOrEqual:
		return c <= value
	case ThresholdEquals:
		return c == value
	default:
		return false
	}
}

// Threshold is the count comparison a threshold/aggregation rule checks
// (phase11.md §41/§42).
type Threshold struct {
	Operator ThresholdOperator
	Value    float64
}

// Aggregation configures grouping, windowing, and the count comparison
// for TypeThreshold and TypeAggregation rules (phase11.md §7/§41/§42).
type Aggregation struct {
	GroupBy []string
	Window  time.Duration
	// Function defaults to FunctionCount when empty — TypeThreshold
	// rules always use count; TypeAggregation rules may use count or
	// unique_count.
	Function AggregationFunction
	// UniqueField is required when Function is FunctionUniqueCount — the
	// event field whose distinct values are counted (phase11.md §42's
	// "10 unique destination ports").
	UniqueField string
	Threshold   Threshold
}

// SequenceStep is one ordered step of a TypeSequence rule (phase11.md
// §38/§40).
type SequenceStep struct {
	EventType  EventType
	Conditions []Condition
}

// Sequence configures an ordered-event-sequence rule (phase11.md §38/
// §40).
type Sequence struct {
	Steps []SequenceStep
	// GroupBy scopes a sequence to events sharing the same value for
	// these fields (e.g. the same user, the same asset) — optional
	// (phase11.md §40: "do not require every sequence to use every
	// field").
	GroupBy []string
	Window  time.Duration
	// MinEvents defaults to len(Steps) when zero.
	MinEvents int
}

// Definition is one rule's parsed, engine-native logic — the decoded
// form of a persisted RuleVersion.Definition JSON document (phase11.md
// §7). It carries no rule metadata (name, severity display, tags — see
// internal/domain/rule.Rule for that); Definition is purely the
// evaluatable logic, plus the Severity/Confidence a match should carry.
type Definition struct {
	EventType  EventType
	Conditions []Condition

	RuleType    Type
	Aggregation *Aggregation
	Sequence    *Sequence

	Severity   Severity
	Confidence Confidence

	// SchemaVersion declares which normalized-event schema shape this
	// definition was authored against (phase11.md §104/§105).
	SchemaVersion int
}
