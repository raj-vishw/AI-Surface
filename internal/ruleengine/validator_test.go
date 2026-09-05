package ruleengine

import (
	"testing"
	"time"
)

func validFieldMatchDef() Definition {
	return Definition{
		EventType:  EventFinding,
		Conditions: []Condition{{Field: "finding.severity", Operator: OpEquals, Value: "high"}},
		RuleType:   TypeFieldMatch, Severity: SeverityHigh, Confidence: ConfidenceHigh, SchemaVersion: 1,
	}
}

func TestValidator_ValidFieldMatch(t *testing.T) {
	if errs := NewValidator().Validate(validFieldMatchDef()); len(errs) != 0 {
		t.Fatalf("expected no errors, got %v", errs)
	}
}

func TestValidator_InvalidField(t *testing.T) {
	def := validFieldMatchDef()
	def.Conditions = []Condition{{Field: "finding.misspelled_field", Operator: OpEquals, Value: "x"}}
	errs := NewValidator().Validate(def)
	if len(errs) == 0 {
		t.Fatal("expected validation error for unknown field")
	}
	if errs[0].Code != "rule.validation.invalid_field" {
		t.Errorf("expected rule.validation.invalid_field, got %s", errs[0].Code)
	}
}

func TestValidator_InvalidOperator(t *testing.T) {
	def := validFieldMatchDef()
	def.Conditions = []Condition{{Field: "finding.severity", Operator: "arbitrary_expression", Value: "x"}}
	errs := NewValidator().Validate(def)
	found := false
	for _, e := range errs {
		if e.Code == "rule.validation.invalid_operator" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected rule.validation.invalid_operator, got %v", errs)
	}
}

func TestValidator_InvalidType(t *testing.T) {
	def := validFieldMatchDef()
	def.Conditions = []Condition{{Field: "finding.confidence", Operator: OpGreaterThanOrEqual, Value: "not-a-number"}}
	errs := NewValidator().Validate(def)
	found := false
	for _, e := range errs {
		if e.Code == "rule.validation.type_mismatch" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected rule.validation.type_mismatch, got %v", errs)
	}
}

func TestValidator_MissingThreshold(t *testing.T) {
	def := validFieldMatchDef()
	def.RuleType = TypeThreshold
	def.Aggregation = &Aggregation{GroupBy: []string{"finding.category"}, Window: 5 * time.Minute}
	errs := NewValidator().Validate(def)
	found := false
	for _, e := range errs {
		if e.Code == "rule.validation.missing_threshold" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected rule.validation.missing_threshold, got %v", errs)
	}
}

func TestValidator_InvalidWindow(t *testing.T) {
	def := validFieldMatchDef()
	def.RuleType = TypeThreshold
	def.Aggregation = &Aggregation{Window: 0, Threshold: Threshold{Operator: ThresholdGreaterThanOrEqual, Value: 5}}
	errs := NewValidator().Validate(def)
	found := false
	for _, e := range errs {
		if e.Code == "rule.validation.invalid_window" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected rule.validation.invalid_window, got %v", errs)
	}
}

func TestValidator_InvalidSequence_TooFewSteps(t *testing.T) {
	def := validFieldMatchDef()
	def.RuleType = TypeSequence
	def.Sequence = &Sequence{Steps: []SequenceStep{{EventType: EventFinding}}, Window: 10 * time.Minute}
	errs := NewValidator().Validate(def)
	found := false
	for _, e := range errs {
		if e.Code == "rule.validation.invalid_sequence" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected rule.validation.invalid_sequence, got %v", errs)
	}
}

func TestValidator_MalformedSyntax_MissingConditions(t *testing.T) {
	def := validFieldMatchDef()
	def.Conditions = nil
	errs := NewValidator().Validate(def)
	found := false
	for _, e := range errs {
		if e.Code == "rule.validation.missing_conditions" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected rule.validation.missing_conditions, got %v", errs)
	}
}

func TestValidator_UnsafeOperatorNeverExecutesArbitraryCode(t *testing.T) {
	// There is no operator value that causes arbitrary code execution —
	// Operator is a closed string enum; an unrecognized value is always
	// a rejected string, never evaluated.
	def := validFieldMatchDef()
	def.Conditions = []Condition{{Field: "finding.severity", Operator: Operator("os.Exec(rm -rf /)"), Value: "x"}}
	errs := NewValidator().Validate(def)
	if len(errs) == 0 {
		t.Fatal("expected the unrecognized operator to be rejected by validation")
	}
}
