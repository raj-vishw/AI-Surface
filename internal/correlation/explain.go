package correlation

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Explain produces a human-readable statement of why component's nodes
// were grouped together (phase12.md §39/§103) — never an unsupported
// conclusion like "attacker compromised the server" (phase12.md §104):
// it states only what was observed (shared entities, strategies, time
// window, confidence) and closes with a fixed limitation sentence
// (phase12.md §104's worked "better" example).
func Explain(component Graph, score int, confidence Confidence, temporalWindow time.Duration) string {
	var b strings.Builder

	fmt.Fprintf(&b, "%d observation(s) across %d relationship(s) were grouped by the following signals:\n", len(component.Nodes), len(component.Edges))

	strategies := map[string]bool{}
	for _, e := range component.Edges {
		strategies[e.StrategyID] = true
	}
	names := make([]string, 0, len(strategies))
	for id := range strategies {
		names = append(names, id)
	}
	sort.Strings(names)
	for _, id := range names {
		b.WriteString("- Strategy: " + id + "\n")
	}
	for _, e := range component.Edges {
		b.WriteString("- " + e.Evidence + "\n")
	}

	if first, last, ok := observedSpan(component); ok {
		fmt.Fprintf(&b, "Observations span %s (correlation window: %s).\n", last.Sub(first), temporalWindow)
	}

	fmt.Fprintf(&b, "Score: %d. Confidence: %s.\n", score, confidence)
	b.WriteString("This is a correlated grouping of observations, not a confirmed attack — " +
		"an analyst must review the evidence above before treating it as anything more than a lead worth investigating.")

	return b.String()
}

// observedSpan returns component's earliest and latest node Timestamp.
func observedSpan(component Graph) (first, last time.Time, ok bool) {
	for _, n := range component.Nodes {
		if !ok || n.Timestamp.Before(first) {
			first = n.Timestamp
		}
		if !ok || n.Timestamp.After(last) {
			last = n.Timestamp
		}
		ok = true
	}
	return first, last, ok
}
