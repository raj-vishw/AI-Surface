package ruleengine

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Operator names one safe, non-Turing-complete comparison a Condition
// may use (phase11.md §8) — this engine never executes an arbitrary
// expression.
type Operator string

// Recognized operators.
const (
	OpEquals             Operator = "equals"
	OpNotEquals          Operator = "not_equals"
	OpContains           Operator = "contains"
	OpStartsWith         Operator = "starts_with"
	OpEndsWith           Operator = "ends_with"
	OpGreaterThan        Operator = "greater_than"
	OpGreaterThanOrEqual Operator = "greater_than_or_equal"
	OpLessThan           Operator = "less_than"
	OpLessThanOrEqual    Operator = "less_than_or_equal"
	OpIn                 Operator = "in"
	OpNotIn              Operator = "not_in"
	OpExists             Operator = "exists"
	OpNotExists          Operator = "not_exists"
)

var validOperators = map[Operator]bool{
	OpEquals: true, OpNotEquals: true, OpContains: true, OpStartsWith: true, OpEndsWith: true,
	OpGreaterThan: true, OpGreaterThanOrEqual: true, OpLessThan: true, OpLessThanOrEqual: true,
	OpIn: true, OpNotIn: true, OpExists: true, OpNotExists: true,
}

// Valid reports whether o is a recognized operator.
func (o Operator) Valid() bool { return validOperators[o] }

// FieldKind names a field's data type for validation (phase11.md §11).
type FieldKind string

// Recognized field kinds.
const (
	KindString FieldKind = "string"
	KindInt    FieldKind = "int"
	KindFloat  FieldKind = "float"
	KindBool   FieldKind = "bool"
	KindTime   FieldKind = "time"
)

// stringOperators/orderedOperators/equalityOperators/setOperators/
// presenceOperators name which operators are compatible with which
// field kinds (phase11.md §12's "operator compatibility" validation).
var stringOnlyOperators = map[Operator]bool{OpContains: true, OpStartsWith: true, OpEndsWith: true}
var orderedOperators = map[Operator]bool{
	OpGreaterThan: true, OpGreaterThanOrEqual: true, OpLessThan: true, OpLessThanOrEqual: true,
}
var equalityOperators = map[Operator]bool{OpEquals: true, OpNotEquals: true}
var setOperators = map[Operator]bool{OpIn: true, OpNotIn: true}
var presenceOperators = map[Operator]bool{OpExists: true, OpNotExists: true}

// OperatorCompatibleWithKind reports whether operator may be used
// against a field of kind — e.g. "contains" only ever applies to a
// string field; "greater_than" only to int/float/time (phase11.md §12).
func OperatorCompatibleWithKind(op Operator, kind FieldKind) bool {
	switch {
	case presenceOperators[op]:
		return true // exists/not_exists apply to any field kind
	case setOperators[op]:
		return true // in/not_in apply to any field kind (value is a list)
	case equalityOperators[op]:
		return true // equals/not_equals apply to any field kind
	case stringOnlyOperators[op]:
		return kind == KindString
	case orderedOperators[op]:
		return kind == KindInt || kind == KindFloat || kind == KindTime
	default:
		return false
	}
}

// Condition is one safe field comparison (phase11.md §7/§8).
type Condition struct {
	Field    string
	Operator Operator
	Value    any
}

// FieldDef describes one field this engine recognizes.
type FieldDef struct {
	Name string
	Kind FieldKind
}

// FieldSchema is the closed set of fields a rule may reference for one
// EventType (phase11.md §9's "use the existing normalized event
// schema" — here, this platform's own normalized findings/assets/
// endpoints/fingerprints/intelligence records, not a raw log format).
// Referencing anything outside this set is a validation error
// (phase11.md §10), never silently treated as null.
type FieldSchema map[EventType]map[string]FieldKind

// DefaultSchema is the built-in field schema every rule validates
// against, generated from BuiltinFieldDefs.
var DefaultSchema = buildSchema()

// BuiltinFieldDefs enumerates every field this engine recognizes, by
// event type. Every field name is namespaced by its source
// ("finding.severity", "asset.type", ...), mirroring phase11.md §9's own
// "authentication.user"/"http.status" namespacing convention, adapted to
// this platform's actual normalized entities (findings, assets,
// endpoints, technology fingerprints, threat intelligence) rather than
// authentication/HTTP/process logs this platform does not ingest.
var BuiltinFieldDefs = map[EventType][]FieldDef{
	EventFinding: {
		{"event.timestamp", KindTime}, {"event.target_id", KindString}, {"event.asset_id", KindString},
		{"finding.severity", KindString}, {"finding.confidence", KindFloat}, {"finding.category", KindString},
		{"finding.status", KindString}, {"finding.detector_id", KindString}, {"finding.scope", KindString},
	},
	EventAssetObservation: {
		{"event.timestamp", KindTime}, {"event.target_id", KindString}, {"event.asset_id", KindString},
		{"asset.type", KindString}, {"asset.status", KindString}, {"asset.confidence", KindFloat},
		{"asset.hostname", KindString}, {"asset.ip", KindString}, {"asset.source", KindString},
	},
	EventEndpointObservation: {
		{"event.timestamp", KindTime}, {"event.target_id", KindString}, {"event.asset_id", KindString},
		{"endpoint.classification", KindString}, {"endpoint.confidence", KindFloat},
		{"endpoint.method", KindString}, {"endpoint.status", KindString},
	},
	EventFingerprintChange: {
		{"event.timestamp", KindTime}, {"event.target_id", KindString}, {"event.asset_id", KindString},
		{"fingerprint.technology", KindString}, {"fingerprint.category", KindString},
		{"fingerprint.confidence", KindFloat}, {"fingerprint.status", KindString},
	},
	EventIntelligenceRecord: {
		{"event.timestamp", KindTime}, {"event.target_id", KindString}, {"event.asset_id", KindString},
		{"intelligence.verdict", KindString}, {"intelligence.confidence", KindString},
		{"intelligence.category", KindString}, {"intelligence.source_type", KindString},
		{"intelligence.indicator_type", KindString},
	},
}

func buildSchema() FieldSchema {
	schema := FieldSchema{}
	for eventType, defs := range BuiltinFieldDefs {
		fields := map[string]FieldKind{}
		for _, d := range defs {
			fields[d.Name] = d.Kind
		}
		schema[eventType] = fields
	}
	return schema
}

// FieldKind looks up field's kind for eventType, reporting false if the
// field is unknown for that event type (phase11.md §10).
func (s FieldSchema) FieldKind(eventType EventType, field string) (FieldKind, bool) {
	fields, ok := s[eventType]
	if !ok {
		return "", false
	}
	kind, ok := fields[field]
	return kind, ok
}

// Evaluate reports whether c holds against event's fields — an
// unrecognized field or an operator/value type mismatch is reported as
// an error, never treated as a silent non-match (phase11.md §10/§11).
// Callers should validate a Definition once (see Validator) rather than
// relying on Evaluate's own error return for routine rule authoring
// mistakes; Evaluate still checks defensively since Fields is untyped.
func (c Condition) Evaluate(event Event) (bool, error) {
	kind, ok := DefaultSchema.FieldKind(event.Type, c.Field)
	if !ok {
		return false, fmt.Errorf("unknown field %q for event type %q", c.Field, event.Type)
	}
	if !OperatorCompatibleWithKind(c.Operator, kind) {
		return false, fmt.Errorf("operator %q is not compatible with field %q (kind %q)", c.Operator, c.Field, kind)
	}

	value, present := event.Fields[c.Field]

	switch c.Operator {
	case OpExists:
		return present, nil
	case OpNotExists:
		return !present, nil
	}
	if !present {
		// Every other operator requires the field to actually be
		// present — absence is never silently coerced into a match or
		// non-match by comparison (phase11.md §10).
		return false, nil
	}

	switch c.Operator {
	case OpEquals:
		return compareEqual(value, c.Value)
	case OpNotEquals:
		eq, err := compareEqual(value, c.Value)
		return !eq, err
	case OpContains, OpStartsWith, OpEndsWith:
		return compareString(c.Operator, value, c.Value)
	case OpGreaterThan, OpGreaterThanOrEqual, OpLessThan, OpLessThanOrEqual:
		return compareOrdered(c.Operator, value, c.Value)
	case OpIn, OpNotIn:
		return compareSet(c.Operator, value, c.Value)
	default:
		return false, fmt.Errorf("unsupported operator %q", c.Operator)
	}
}

func compareEqual(a, b any) (bool, error) {
	af, aok := asFloat(a)
	bf, bok := asFloat(b)
	if aok && bok {
		return af == bf, nil
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b), nil
}

func compareString(op Operator, a, b any) (bool, error) {
	as, ok := a.(string)
	if !ok {
		return false, fmt.Errorf("value %v is not a string", a)
	}
	bs, ok := b.(string)
	if !ok {
		return false, fmt.Errorf("comparison value %v is not a string", b)
	}
	switch op {
	case OpContains:
		return strings.Contains(as, bs), nil
	case OpStartsWith:
		return strings.HasPrefix(as, bs), nil
	case OpEndsWith:
		return strings.HasSuffix(as, bs), nil
	default:
		return false, fmt.Errorf("unsupported string operator %q", op)
	}
}

func compareOrdered(op Operator, a, b any) (bool, error) {
	if at, ok := a.(time.Time); ok {
		bt, ok := asTime(b)
		if !ok {
			return false, fmt.Errorf("comparison value %v is not a time", b)
		}
		return compareOrderedInt(op, at.Compare(bt)), nil
	}
	af, ok := asFloat(a)
	if !ok {
		return false, fmt.Errorf("value %v is not numeric — cannot use operator %q", a, op)
	}
	bf, ok := asFloat(b)
	if !ok {
		return false, fmt.Errorf("comparison value %v is not numeric (phase11.md §11: cannot compare a number field against a non-numeric value)", b)
	}
	cmp := 0
	switch {
	case af < bf:
		cmp = -1
	case af > bf:
		cmp = 1
	}
	return compareOrderedInt(op, cmp), nil
}

func compareOrderedInt(op Operator, cmp int) bool {
	switch op {
	case OpGreaterThan:
		return cmp > 0
	case OpGreaterThanOrEqual:
		return cmp >= 0
	case OpLessThan:
		return cmp < 0
	case OpLessThanOrEqual:
		return cmp <= 0
	default:
		return false
	}
}

func compareSet(op Operator, value, set any) (bool, error) {
	list, ok := set.([]any)
	if !ok {
		return false, fmt.Errorf("comparison value for %q must be a list", op)
	}
	found := false
	for _, item := range list {
		if eq, _ := compareEqual(value, item); eq {
			found = true
			break
		}
	}
	if op == OpNotIn {
		return !found, nil
	}
	return found, nil
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case string:
		f, err := strconv.ParseFloat(n, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}

func asTime(v any) (time.Time, bool) {
	switch t := v.(type) {
	case time.Time:
		return t, true
	case string:
		parsed, err := time.Parse(time.RFC3339, t)
		if err != nil {
			return time.Time{}, false
		}
		return parsed, true
	default:
		return time.Time{}, false
	}
}
