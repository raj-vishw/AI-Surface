package ruleengine

import "fmt"

// ValidationError is one structured rule-validation failure
// (phase11.md §12's "return structured errors" — e.g.
// "rule.validation.invalid_field").
type ValidationError struct {
	Code    string
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s (%s): %s", e.Code, e.Field, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// ValidationErrors is a non-empty collection of ValidationError.
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "no validation errors"
	}
	s := e[0].Error()
	for _, extra := range e[1:] {
		s += "; " + extra.Error()
	}
	return s
}

var validSeverities = map[Severity]bool{
	SeverityInformational: true, SeverityLow: true, SeverityMedium: true, SeverityHigh: true, SeverityCritical: true,
}
var validConfidences = map[Confidence]bool{
	ConfidenceVeryLow: true, ConfidenceLow: true, ConfidenceMedium: true, ConfidenceHigh: true, ConfidenceVeryHigh: true,
}
var validThresholdOperators = map[ThresholdOperator]bool{
	ThresholdGreaterThan: true, ThresholdGreaterThanOrEqual: true, ThresholdLessThan: true,
	ThresholdLessThanOrEqual: true, ThresholdEquals: true,
}

// Validator validates a Definition against a FieldSchema (phase11.md
// §12). A zero Validator uses DefaultSchema.
type Validator struct {
	Schema FieldSchema
}

// NewValidator builds a Validator over DefaultSchema.
func NewValidator() *Validator { return &Validator{Schema: DefaultSchema} }

// Validate checks def for syntax/schema/type/operator/aggregation/
// sequence/severity/confidence errors (phase11.md §12), returning every
// error found rather than stopping at the first.
func (v *Validator) Validate(def Definition) ValidationErrors {
	schema := v.Schema
	if schema == nil {
		schema = DefaultSchema
	}
	var errs ValidationErrors

	if !def.EventType.Valid() {
		errs = append(errs, ValidationError{"rule.validation.invalid_field", "event_type", "unrecognized event type"})
	} else if _, ok := schema[def.EventType]; !ok {
		errs = append(errs, ValidationError{"rule.validation.invalid_field", "event_type", "no field schema registered for this event type"})
	}

	if !validSeverities[def.Severity] {
		errs = append(errs, ValidationError{"rule.validation.invalid_severity", "severity", "unrecognized severity"})
	}
	if !validConfidences[def.Confidence] {
		errs = append(errs, ValidationError{"rule.validation.invalid_confidence", "confidence", "unrecognized confidence level"})
	}
	if def.SchemaVersion < 1 {
		errs = append(errs, ValidationError{"rule.validation.invalid_schema_version", "schema_version", "must be at least 1"})
	}

	errs = append(errs, v.validateConditions(schema, def.EventType, def.Conditions, "conditions")...)

	switch def.RuleType {
	case TypeFieldMatch:
		if len(def.Conditions) == 0 {
			errs = append(errs, ValidationError{"rule.validation.missing_conditions", "conditions", "field_match rules require at least one condition"})
		}
	case TypeThreshold:
		errs = append(errs, v.validateAggregation(schema, def)...)
	case TypeAggregation:
		errs = append(errs, v.validateAggregation(schema, def)...)
	case TypeSequence:
		errs = append(errs, v.validateSequence(schema, def)...)
	default:
		errs = append(errs, ValidationError{"rule.validation.invalid_rule_type", "rule_type", "unrecognized rule type"})
	}

	return errs
}

func (v *Validator) validateConditions(schema FieldSchema, eventType EventType, conditions []Condition, path string) ValidationErrors {
	var errs ValidationErrors
	for i, c := range conditions {
		field := fmt.Sprintf("%s[%d]", path, i)
		if !c.Operator.Valid() {
			errs = append(errs, ValidationError{"rule.validation.invalid_operator", field, fmt.Sprintf("unrecognized operator %q", c.Operator)})
			continue
		}
		kind, ok := schema.FieldKind(eventType, c.Field)
		if !ok {
			errs = append(errs, ValidationError{"rule.validation.invalid_field", field, fmt.Sprintf("unknown field %q for event type %q", c.Field, eventType)})
			continue
		}
		if !OperatorCompatibleWithKind(c.Operator, kind) {
			errs = append(errs, ValidationError{"rule.validation.incompatible_operator", field,
				fmt.Sprintf("operator %q is not compatible with field %q (kind %q)", c.Operator, c.Field, kind)})
			continue
		}
		if err := validateValueType(c.Operator, kind, c.Value); err != nil {
			errs = append(errs, ValidationError{"rule.validation.type_mismatch", field, err.Error()})
		}
	}
	return errs
}

// validateValueType implements phase11.md §11: a numeric field may not
// be compared against an arbitrary string, etc.
func validateValueType(op Operator, kind FieldKind, value any) error {
	if presenceOperators[op] {
		return nil // exists/not_exists carry no comparison value
	}
	if setOperators[op] {
		if _, ok := value.([]any); !ok {
			return fmt.Errorf("operator %q requires a list value", op)
		}
		return nil
	}
	switch kind {
	case KindInt, KindFloat:
		if _, ok := asFloat(value); !ok {
			return fmt.Errorf("field of kind %q cannot be compared against non-numeric value %v", kind, value)
		}
	case KindTime:
		if _, ok := asTime(value); !ok {
			return fmt.Errorf("field of kind %q cannot be compared against non-time value %v", kind, value)
		}
	case KindString:
		if _, ok := value.(string); !ok && equalityOperators[op] {
			return fmt.Errorf("field of kind %q cannot be compared against non-string value %v", kind, value)
		}
	}
	return nil
}

func (v *Validator) validateAggregation(schema FieldSchema, def Definition) ValidationErrors {
	var errs ValidationErrors
	if def.Aggregation == nil {
		errs = append(errs, ValidationError{"rule.validation.missing_aggregation", "aggregation", "threshold/aggregation rules require an aggregation configuration"})
		return errs
	}
	agg := def.Aggregation
	if agg.Window <= 0 {
		errs = append(errs, ValidationError{"rule.validation.invalid_window", "aggregation.window", "must be a positive duration"})
	}
	if !validThresholdOperators[agg.Threshold.Operator] {
		errs = append(errs, ValidationError{"rule.validation.missing_threshold", "aggregation.threshold", "must specify a recognized threshold operator"})
	}
	if agg.Function == FunctionUniqueCount {
		if agg.UniqueField == "" {
			errs = append(errs, ValidationError{"rule.validation.missing_unique_field", "aggregation.unique_field", "unique_count requires unique_field"})
		} else if _, ok := schema.FieldKind(def.EventType, agg.UniqueField); !ok {
			errs = append(errs, ValidationError{"rule.validation.invalid_field", "aggregation.unique_field", fmt.Sprintf("unknown field %q for event type %q", agg.UniqueField, def.EventType)})
		}
	} else if agg.Function != "" && agg.Function != FunctionCount {
		errs = append(errs, ValidationError{"rule.validation.invalid_aggregation_function", "aggregation.function", "must be count or unique_count"})
	}
	for i, field := range agg.GroupBy {
		if _, ok := schema.FieldKind(def.EventType, field); !ok {
			errs = append(errs, ValidationError{"rule.validation.invalid_field", fmt.Sprintf("aggregation.group_by[%d]", i), fmt.Sprintf("unknown field %q for event type %q", field, def.EventType)})
		}
	}
	return errs
}

func (v *Validator) validateSequence(schema FieldSchema, def Definition) ValidationErrors {
	var errs ValidationErrors
	if def.Sequence == nil {
		errs = append(errs, ValidationError{"rule.validation.missing_sequence", "sequence", "sequence rules require a sequence configuration"})
		return errs
	}
	seq := def.Sequence
	if len(seq.Steps) < 2 {
		errs = append(errs, ValidationError{"rule.validation.invalid_sequence", "sequence.steps", "a sequence requires at least 2 ordered steps"})
	}
	if seq.Window <= 0 {
		errs = append(errs, ValidationError{"rule.validation.invalid_window", "sequence.window", "must be a positive duration"})
	}
	for i, step := range seq.Steps {
		if !step.EventType.Valid() {
			errs = append(errs, ValidationError{"rule.validation.invalid_field", fmt.Sprintf("sequence.steps[%d].event_type", i), "unrecognized event type"})
			continue
		}
		errs = append(errs, v.validateConditions(schema, step.EventType, step.Conditions, fmt.Sprintf("sequence.steps[%d].conditions", i))...)
	}
	for i, field := range seq.GroupBy {
		// GroupBy fields must exist on every step's event type — a
		// sequence field only makes sense if every step can supply it.
		for j, step := range seq.Steps {
			if _, ok := schema.FieldKind(step.EventType, field); !ok {
				errs = append(errs, ValidationError{"rule.validation.invalid_field", fmt.Sprintf("sequence.group_by[%d]", i),
					fmt.Sprintf("field %q is not available on step[%d]'s event type %q", field, j, step.EventType)})
			}
		}
	}
	return errs
}
