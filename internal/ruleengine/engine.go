package ruleengine

import (
	"context"
	"fmt"
	"sort"
)

// Engine evaluates one CompiledRule against a slice of Events. It
// performs no persistence and no data-fetching of its own — see
// internal/service/rule for both. Evaluation is deterministic: the same
// rule version, event dataset, and configuration always produce the
// same matches (phase11.md §14/§55), since every step here (filtering,
// grouping, windowing) is a pure function of its inputs.
type Engine struct{}

// NewEngine builds an Engine.
func NewEngine() *Engine { return &Engine{} }

// Evaluate dispatches to the evaluation strategy for def.RuleType. It
// checks ctx once at the start — a single Evaluate call operates on an
// already-fetched, bounded slice of Events (internal/service/rule is
// responsible for bounding how many events one evaluation considers,
// phase11.md §59/§89), so no further cancellation checkpoints are
// needed within one call.
func (e *Engine) Evaluate(ctx context.Context, compiled *CompiledRule, events []Event) ([]Match, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if compiled == nil {
		return nil, fmt.Errorf("compiled rule must not be nil")
	}
	def := compiled.Definition

	switch def.RuleType {
	case TypeFieldMatch:
		return evaluateFieldMatch(def, events), nil
	case TypeThreshold, TypeAggregation:
		return evaluateAggregation(def, events), nil
	case TypeSequence:
		return evaluateSequence(def, events), nil
	default:
		return nil, fmt.Errorf("unsupported rule type %q", def.RuleType)
	}
}

// matchesConditions reports whether event satisfies every condition —
// an error from any condition (unknown field, type mismatch) makes the
// event a non-match rather than panicking; internal/service/rule is
// expected to validate a Definition (see Compile) before ever handing it
// to Evaluate, so a condition error here indicates a Fields-assembly
// bug in the event-projection code, not a rule-authoring mistake.
func matchesConditions(event Event, conditions []Condition) bool {
	for _, c := range conditions {
		ok, err := c.Evaluate(event)
		if err != nil || !ok {
			return false
		}
	}
	return true
}

func evaluateFieldMatch(def Definition, events []Event) []Match {
	var matches []Match
	for _, event := range events {
		if event.Type != def.EventType {
			continue
		}
		if !matchesConditions(event, def.Conditions) {
			continue
		}
		matches = append(matches, Match{
			Events: []Event{event}, WindowStart: event.Timestamp, WindowEnd: event.Timestamp,
			Severity: def.Severity, Confidence: def.Confidence,
		})
	}
	return matches
}

// groupKeyOf builds the stringified group-by key for event — fields
// absent on event are represented as "" so grouping is still
// deterministic (validated field existence at Compile time means this
// only happens for a field genuinely inapplicable to this specific
// event, not a typo).
func groupKeyOf(event Event, groupBy []string) map[string]string {
	key := make(map[string]string, len(groupBy))
	for _, field := range groupBy {
		if v, ok := event.Fields[field]; ok {
			key[field] = fmt.Sprintf("%v", v)
		} else {
			key[field] = ""
		}
	}
	return key
}

func groupKeyString(key map[string]string, groupBy []string) string {
	s := ""
	for _, field := range groupBy {
		s += field + "=" + key[field] + "|"
	}
	return s
}

// evaluateAggregation implements both TypeThreshold and TypeAggregation
// (the same grouping/windowing/threshold machinery; TypeThreshold is
// simply TypeAggregation with Function == FunctionCount). Windowing uses
// FIXED, non-overlapping buckets of Aggregation.Window duration,
// aligned to the Unix epoch via time.Time.Truncate — the simplest
// implementation compatible with this architecture (phase11.md §43),
// chosen over a true sliding window to keep results deterministic and
// avoid emitting a combinatorial number of overlapping near-duplicate
// matches for one sustained pattern (downstream deduplication, see
// ComputeFingerprint, then collapses repeat evaluations of the same
// bucket rather than the engine needing to). Window boundaries are
// half-open [start, end) throughout (phase11.md §44).
func evaluateAggregation(def Definition, events []Event) []Match {
	agg := def.Aggregation
	function := agg.Function
	if function == "" {
		function = FunctionCount
	}

	type bucketKey struct {
		group  string
		bucket int64 // Unix seconds of the truncated window start
	}
	buckets := map[bucketKey][]Event{}
	groupKeys := map[string]map[string]string{}

	for _, event := range events {
		if event.Type != def.EventType {
			continue
		}
		if !matchesConditions(event, def.Conditions) {
			continue
		}
		key := groupKeyOf(event, agg.GroupBy)
		keyStr := groupKeyString(key, agg.GroupBy)
		groupKeys[keyStr] = key
		bucketStart := event.Timestamp.Truncate(agg.Window)
		bk := bucketKey{group: keyStr, bucket: bucketStart.Unix()}
		buckets[bk] = append(buckets[bk], event)
	}

	var matches []Match
	for bk, bucketEvents := range buckets {
		count := len(bucketEvents)
		if function == FunctionUniqueCount {
			seen := map[string]bool{}
			for _, e := range bucketEvents {
				if v, ok := e.Fields[agg.UniqueField]; ok {
					seen[fmt.Sprintf("%v", v)] = true
				}
			}
			count = len(seen)
		}
		if !agg.Threshold.Operator.Satisfies(count, agg.Threshold.Value) {
			continue
		}

		sort.Slice(bucketEvents, func(i, j int) bool { return bucketEvents[i].Timestamp.Before(bucketEvents[j].Timestamp) })
		windowStart := bucketEvents[0].Timestamp.Truncate(agg.Window)
		matches = append(matches, Match{
			GroupKey: groupKeys[bk.group], Events: bucketEvents,
			WindowStart: windowStart, WindowEnd: windowStart.Add(agg.Window),
			Severity: def.Severity, Confidence: def.Confidence,
		})
	}
	return matches
}

// evaluateSequence implements ordered-event-sequence detection
// (phase11.md §38/§40) via a single deterministic left-to-right scan per
// group: a state machine advances to the next step only when an event
// satisfying that step's conditions is observed after the previous
// step's event, all within Sequence.Window of the sequence's first
// event. This finds one non-overlapping sequence at a time per group
// (documented limitation: a busier interleaving of multiple concurrent
// candidate sequences in one group may not find every possible
// combination — see docs/architecture/detection-engine.md's Known
// Limitations) — never non-deterministic, never silently reordering
// events (event ordering is by Timestamp throughout).
func evaluateSequence(def Definition, events []Event) []Match {
	seq := def.Sequence

	type group struct {
		key    map[string]string
		events []Event
	}
	groups := map[string]*group{}
	for _, event := range events {
		stepIdx := stepMatching(event, seq.Steps)
		if stepIdx < 0 {
			continue
		}
		key := groupKeyOf(event, seq.GroupBy)
		keyStr := groupKeyString(key, seq.GroupBy)
		g, ok := groups[keyStr]
		if !ok {
			g = &group{key: key}
			groups[keyStr] = g
		}
		g.events = append(g.events, event)
	}

	var matches []Match
	for _, g := range groups {
		sort.Slice(g.events, func(i, j int) bool { return g.events[i].Timestamp.Before(g.events[j].Timestamp) })
		matches = append(matches, scanSequence(def, seq, g.key, g.events)...)
	}
	return matches
}

// stepMatching returns the index of the first step whose EventType and
// Conditions event satisfies, or -1 if it matches no step.
func stepMatching(event Event, steps []SequenceStep) int {
	for i, step := range steps {
		if event.Type != step.EventType {
			continue
		}
		if matchesConditions(event, step.Conditions) {
			return i
		}
	}
	return -1
}

func scanSequence(def Definition, seq *Sequence, groupKey map[string]string, events []Event) []Match {
	var matches []Match
	nextStep := 0
	var current []Event

	for _, event := range events {
		idx := stepMatching(event, seq.Steps)
		if idx != nextStep {
			// Not the step we're waiting for. If it matches step 0,
			// restart the candidate sequence from here instead of
			// discarding it entirely.
			if idx == 0 {
				current = []Event{event}
				nextStep = 1
			}
			continue
		}

		current = append(current, event)
		nextStep++

		if len(current) > 1 && current[len(current)-1].Timestamp.Sub(current[0].Timestamp) > seq.Window {
			// The sequence overran its window — drop it and, if this
			// event could itself start a new candidate, restart there.
			if idx == 0 {
				current = []Event{event}
				nextStep = 1
			} else {
				current = nil
				nextStep = 0
			}
			continue
		}

		if nextStep == len(seq.Steps) {
			windowStart := current[0].Timestamp
			matches = append(matches, Match{
				GroupKey: groupKey, Events: append([]Event{}, current...),
				WindowStart: windowStart, WindowEnd: current[len(current)-1].Timestamp,
				Severity: def.Severity, Confidence: def.Confidence,
			})
			current = nil
			nextStep = 0
		}
	}
	return matches
}
