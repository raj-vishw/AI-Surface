package ruleengine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// CompiledRule is a validated Definition ready for repeated evaluation
// (phase11.md §13's "Rule Definition -> Validation -> Compilation ->
// Evaluation" pipeline). Compilation here means "validated once, hashed
// once" rather than a literal bytecode step — this engine's rule
// language is small and closed (phase11.md §6), so Definition itself
// already is the efficient evaluation-ready form; there is no separate
// intermediate representation to build. Callers (internal/service/rule)
// are expected to cache a CompiledRule per (RuleID, RuleVersion) rather
// than re-validating on every evaluation (phase11.md §13).
type CompiledRule struct {
	Definition Definition
	Hash       string
}

// Compile validates def and returns a CompiledRule, or the validation
// errors if def is invalid. Compilation never partially succeeds — an
// invalid definition never produces a CompiledRule (phase11.md §71:
// "do not execute imported rules during import" applies equally to any
// invalid definition, imported or authored directly).
func Compile(def Definition) (*CompiledRule, error) {
	if errs := NewValidator().Validate(def); len(errs) > 0 {
		return nil, errs
	}
	return &CompiledRule{Definition: def, Hash: NormalizedHash(def)}, nil
}

// normalizedForHash is the subset of Definition that participates in
// NormalizedHash — deliberately excludes nothing from Definition itself
// (Definition carries no timestamps/database IDs/mutable metadata to
// begin with; those live on internal/domain/rule.Version, never
// inside the hashed Definition — phase11.md §73).
type normalizedForHash struct {
	EventType     EventType    `json:"event_type"`
	Conditions    []Condition  `json:"conditions"`
	RuleType      Type         `json:"rule_type"`
	Aggregation   *Aggregation `json:"aggregation,omitempty"`
	Sequence      *Sequence    `json:"sequence,omitempty"`
	Severity      Severity     `json:"severity"`
	Confidence    Confidence   `json:"confidence"`
	SchemaVersion int          `json:"schema_version"`
}

// NormalizedHash returns a stable SHA-256 hex digest of def's
// semantically-meaningful content (phase11.md §72/§73) — two
// definitions with identical logic hash identically regardless of Go
// map/slice construction order, since GroupBy/Tags-shaped slices are
// sorted before encoding and encoding/json already sorts map keys.
func NormalizedHash(def Definition) string {
	normalized := normalizedForHash{
		EventType: def.EventType, Conditions: sortedConditions(def.Conditions),
		RuleType: def.RuleType, Severity: def.Severity, Confidence: def.Confidence, SchemaVersion: def.SchemaVersion,
	}
	if def.Aggregation != nil {
		agg := *def.Aggregation
		agg.GroupBy = sortedStrings(agg.GroupBy)
		normalized.Aggregation = &agg
	}
	if def.Sequence != nil {
		seq := *def.Sequence
		seq.GroupBy = sortedStrings(seq.GroupBy)
		steps := make([]SequenceStep, len(seq.Steps))
		for i, step := range seq.Steps {
			steps[i] = SequenceStep{EventType: step.EventType, Conditions: sortedConditions(step.Conditions)}
		}
		seq.Steps = steps
		normalized.Sequence = &seq
	}

	encoded, err := json.Marshal(normalized)
	if err != nil {
		// Definition's fields are all JSON-safe (strings, primitives,
		// slices of the same) — Marshal failing here would indicate a
		// programming error, not a runtime condition callers should
		// handle differently.
		panic(fmt.Sprintf("ruleengine: encoding definition for hashing: %v", err))
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func sortedConditions(conditions []Condition) []Condition {
	out := make([]Condition, len(conditions))
	copy(out, conditions)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Field != out[j].Field {
			return out[i].Field < out[j].Field
		}
		return out[i].Operator < out[j].Operator
	})
	return out
}

func sortedStrings(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}
