// This file (parser.go) converts between the human-authored rule schema
// (phase11.md §7's JSON/YAML shape) and this engine's native Definition.
// Both JSON and YAML are supported for import/export (phase11.md §69/
// §70) using gopkg.in/yaml.v3, a dependency already present in this
// project's go.mod (internal/config already uses it) — no new dependency
// is added (phase11.md's own "follow existing project conventions" for
// schema format, and this project's zero-new-third-party-dependency
// discipline). See types.go for this package's own doc comment.

package ruleengine

import (
	"encoding/json"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// rawWindow mirrors phase11.md §7's own worked example shape
// (`window: { duration: 5m }`) rather than a bare duration string, for
// schema fidelity with the master specification.
type rawWindow struct {
	Duration string `json:"duration" yaml:"duration"`
}

type rawThreshold struct {
	Operator string  `json:"operator" yaml:"operator"`
	Value    float64 `json:"value" yaml:"value"`
}

type rawCondition struct {
	Field    string `json:"field" yaml:"field"`
	Operator string `json:"operator" yaml:"operator"`
	Value    any    `json:"value" yaml:"value"`
}

type rawAggregation struct {
	GroupBy     []string     `json:"group_by,omitempty" yaml:"group_by,omitempty"`
	Window      rawWindow    `json:"window" yaml:"window"`
	Function    string       `json:"function,omitempty" yaml:"function,omitempty"`
	UniqueField string       `json:"unique_field,omitempty" yaml:"unique_field,omitempty"`
	Threshold   rawThreshold `json:"threshold" yaml:"threshold"`
}

type rawSequenceStep struct {
	EventType  string         `json:"event_type" yaml:"event_type"`
	Conditions []rawCondition `json:"conditions,omitempty" yaml:"conditions,omitempty"`
}

type rawSequence struct {
	Steps     []rawSequenceStep `json:"steps" yaml:"steps"`
	GroupBy   []string          `json:"group_by,omitempty" yaml:"group_by,omitempty"`
	Window    rawWindow         `json:"window" yaml:"window"`
	MinEvents int               `json:"min_events,omitempty" yaml:"min_events,omitempty"`
}

// rawDefinition is the wire/authoring shape a rule definition is
// imported/exported as (phase11.md §7/§69/§70).
type rawDefinition struct {
	Name          string          `json:"name,omitempty" yaml:"name,omitempty"`
	EventType     string          `json:"event_type" yaml:"event_type"`
	Conditions    []rawCondition  `json:"conditions,omitempty" yaml:"conditions,omitempty"`
	RuleType      string          `json:"rule_type" yaml:"rule_type"`
	Aggregation   *rawAggregation `json:"aggregation,omitempty" yaml:"aggregation,omitempty"`
	Sequence      *rawSequence    `json:"sequence,omitempty" yaml:"sequence,omitempty"`
	Severity      string          `json:"severity" yaml:"severity"`
	Confidence    string          `json:"confidence" yaml:"confidence"`
	SchemaVersion int             `json:"schema_version,omitempty" yaml:"schema_version,omitempty"`
}

func toRawConditions(conditions []Condition) []rawCondition {
	out := make([]rawCondition, len(conditions))
	for i, c := range conditions {
		out[i] = rawCondition{Field: c.Field, Operator: string(c.Operator), Value: c.Value}
	}
	return out
}

func fromRawConditions(raw []rawCondition) []Condition {
	out := make([]Condition, len(raw))
	for i, c := range raw {
		out[i] = Condition{Field: c.Field, Operator: Operator(c.Operator), Value: c.Value}
	}
	return out
}

func toRaw(def Definition) rawDefinition {
	raw := rawDefinition{
		EventType: string(def.EventType), Conditions: toRawConditions(def.Conditions),
		RuleType: string(def.RuleType), Severity: string(def.Severity), Confidence: string(def.Confidence),
		SchemaVersion: def.SchemaVersion,
	}
	if def.Aggregation != nil {
		raw.Aggregation = &rawAggregation{
			GroupBy: def.Aggregation.GroupBy, Window: rawWindow{Duration: def.Aggregation.Window.String()},
			Function: string(def.Aggregation.Function), UniqueField: def.Aggregation.UniqueField,
			Threshold: rawThreshold{Operator: string(def.Aggregation.Threshold.Operator), Value: def.Aggregation.Threshold.Value},
		}
	}
	if def.Sequence != nil {
		steps := make([]rawSequenceStep, len(def.Sequence.Steps))
		for i, s := range def.Sequence.Steps {
			steps[i] = rawSequenceStep{EventType: string(s.EventType), Conditions: toRawConditions(s.Conditions)}
		}
		raw.Sequence = &rawSequence{
			Steps: steps, GroupBy: def.Sequence.GroupBy, Window: rawWindow{Duration: def.Sequence.Window.String()},
			MinEvents: def.Sequence.MinEvents,
		}
	}
	return raw
}

func fromRaw(raw rawDefinition) (Definition, error) {
	def := Definition{
		EventType: EventType(raw.EventType), Conditions: fromRawConditions(raw.Conditions),
		RuleType: Type(raw.RuleType), Severity: Severity(raw.Severity), Confidence: Confidence(raw.Confidence),
		SchemaVersion: raw.SchemaVersion,
	}
	if raw.Aggregation != nil {
		window, err := time.ParseDuration(raw.Aggregation.Window.Duration)
		if err != nil {
			return Definition{}, fmt.Errorf("parsing aggregation.window.duration %q: %w", raw.Aggregation.Window.Duration, err)
		}
		def.Aggregation = &Aggregation{
			GroupBy: raw.Aggregation.GroupBy, Window: window,
			Function: AggregationFunction(raw.Aggregation.Function), UniqueField: raw.Aggregation.UniqueField,
			Threshold: Threshold{Operator: ThresholdOperator(raw.Aggregation.Threshold.Operator), Value: raw.Aggregation.Threshold.Value},
		}
	}
	if raw.Sequence != nil {
		window, err := time.ParseDuration(raw.Sequence.Window.Duration)
		if err != nil {
			return Definition{}, fmt.Errorf("parsing sequence.window.duration %q: %w", raw.Sequence.Window.Duration, err)
		}
		steps := make([]SequenceStep, len(raw.Sequence.Steps))
		for i, s := range raw.Sequence.Steps {
			steps[i] = SequenceStep{EventType: EventType(s.EventType), Conditions: fromRawConditions(s.Conditions)}
		}
		def.Sequence = &Sequence{Steps: steps, GroupBy: raw.Sequence.GroupBy, Window: window, MinEvents: raw.Sequence.MinEvents}
	}
	return def, nil
}

// ParseJSON decodes a JSON rule definition document into a Definition —
// never executed, only parsed into data (phase11.md §71).
func ParseJSON(data []byte) (Definition, error) {
	var raw rawDefinition
	if err := json.Unmarshal(data, &raw); err != nil {
		return Definition{}, fmt.Errorf("parsing rule definition JSON: %w", err)
	}
	return fromRaw(raw)
}

// ParseYAML decodes a YAML rule definition document into a Definition.
func ParseYAML(data []byte) (Definition, error) {
	var raw rawDefinition
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return Definition{}, fmt.Errorf("parsing rule definition YAML: %w", err)
	}
	return fromRaw(raw)
}

// EncodeJSON renders def as canonical JSON — this is the exact form
// persisted as internal/domain/rule.Version.Definition.
func EncodeJSON(def Definition) ([]byte, error) {
	data, err := json.MarshalIndent(toRaw(def), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding rule definition JSON: %w", err)
	}
	return data, nil
}

// EncodeYAML renders def as YAML, for `ai-recon detection export
// --format yaml`.
func EncodeYAML(def Definition) ([]byte, error) {
	data, err := yaml.Marshal(toRaw(def))
	if err != nil {
		return nil, fmt.Errorf("encoding rule definition YAML: %w", err)
	}
	return data, nil
}
