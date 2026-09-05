package ruleengine

import "time"

// Match is one Engine.Evaluate result — the in-memory counterpart of
// internal/domain/rule.DetectionMatch, produced entirely from a
// CompiledRule and a slice of Events with no database access of its own
// (phase11.md §1/§14).
type Match struct {
	// GroupKey is the aggregation/sequence group-by values that produced
	// this match (field name -> stringified value), empty for
	// TypeFieldMatch (which has no grouping).
	GroupKey map[string]string
	// Events is every event that contributed to this match, ordered by
	// Timestamp — the evidence (phase11.md §17): never merely "rule
	// matched" with no reference to what caused it.
	Events []Event

	WindowStart time.Time
	WindowEnd   time.Time

	Severity   Severity
	Confidence Confidence

	// Explanation is set by Explain — see explain.go.
	Explanation string
}

// FirstObserved returns the earliest Events timestamp — the real
// observation time a persisted DetectionMatch records, never the moment
// evaluation happened to run (phase11.md §45). LastObserved below is the
// same kind of accessor for the latest timestamp.
func (m Match) FirstObserved() time.Time {
	if len(m.Events) == 0 {
		return time.Time{}
	}
	first := m.Events[0].Timestamp
	for _, e := range m.Events[1:] {
		if e.Timestamp.Before(first) {
			first = e.Timestamp
		}
	}
	return first
}

// LastObserved returns the latest Events timestamp.
func (m Match) LastObserved() time.Time {
	var last time.Time
	for _, e := range m.Events {
		if e.Timestamp.After(last) {
			last = e.Timestamp
		}
	}
	return last
}
