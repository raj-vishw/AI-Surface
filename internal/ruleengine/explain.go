package ruleengine

import (
	"fmt"
	"sort"
	"strings"
)

// Explain builds a human-readable explanation of why def matched,
// naming the matched conditions, event count, aggregation group,
// window, and threshold where applicable (phase11.md §18/§19) — an
// analyst must be able to understand why a rule fired without reading
// Go source.
func Explain(ruleName string, def Definition, m Match) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Rule: %s\n", ruleName)
	fmt.Fprintf(&b, "Result: matched\n")

	switch def.RuleType {
	case TypeFieldMatch:
		fmt.Fprintf(&b, "Reason: %d event(s) of type %q matched every configured condition.\n", len(m.Events), def.EventType)
		writeConditions(&b, def.Conditions)
	case TypeThreshold:
		fmt.Fprintf(&b, "Reason: %d matching %q events occurred within %s", len(m.Events), def.EventType, def.Aggregation.Window)
		writeGroupKey(&b, m.GroupKey)
		fmt.Fprintf(&b, " (threshold: count %s %g).\n", def.Aggregation.Threshold.Operator, def.Aggregation.Threshold.Value)
		writeConditions(&b, def.Conditions)
	case TypeAggregation:
		verb := "occurred"
		if def.Aggregation.Function == FunctionUniqueCount {
			verb = fmt.Sprintf("distinct values of %q occurred", def.Aggregation.UniqueField)
		}
		fmt.Fprintf(&b, "Reason: %d %s within %s", len(m.Events), verb, def.Aggregation.Window)
		writeGroupKey(&b, m.GroupKey)
		fmt.Fprintf(&b, " (threshold: %s %s %g).\n", def.Aggregation.Function, def.Aggregation.Threshold.Operator, def.Aggregation.Threshold.Value)
	case TypeSequence:
		fmt.Fprintf(&b, "Reason: an ordered sequence of %d steps matched within %s", len(def.Sequence.Steps), def.Sequence.Window)
		writeGroupKey(&b, m.GroupKey)
		b.WriteString(".\n\nSequence matched:\n")
		for _, e := range m.Events {
			fmt.Fprintf(&b, "    %s  %s\n", e.Timestamp.Format("2006-01-02 15:04:05"), e.Type)
		}
	}

	fmt.Fprintf(&b, "\nWindow: [%s, %s)\n", m.WindowStart.Format("2006-01-02T15:04:05Z"), m.WindowEnd.Format("2006-01-02T15:04:05Z"))
	return b.String()
}

func writeGroupKey(b *strings.Builder, groupKey map[string]string) {
	if len(groupKey) == 0 {
		return
	}
	keys := make([]string, 0, len(groupKey))
	for k := range groupKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, groupKey[k]))
	}
	fmt.Fprintf(b, " for %s", strings.Join(parts, ", "))
}

func writeConditions(b *strings.Builder, conditions []Condition) {
	if len(conditions) == 0 {
		return
	}
	b.WriteString("\nMatched conditions:\n")
	for _, c := range conditions {
		fmt.Fprintf(b, "    %s %s %v\n", c.Field, c.Operator, c.Value)
	}
}
