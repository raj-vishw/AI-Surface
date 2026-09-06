package ai

import "sort"

// Limits bounds how much evidence one Context may carry (phase13.md §13).
// Safe, small, always-explicit defaults — never unlimited, the same
// "bounded by default" discipline every prior phase's own Config applies.
type Limits struct {
	// MaxFactsPerType bounds how many facts of any single FactType are
	// kept — e.g. at most this many findings, this many alerts.
	MaxFactsPerType int
	// MaxTotalFacts bounds the context's overall size regardless of type
	// mix.
	MaxTotalFacts int
}

// DefaultMaxFactsPerType/DefaultMaxTotalFacts are the built-in Limits used
// when a caller supplies the zero value.
const (
	DefaultMaxFactsPerType = 25
	DefaultMaxTotalFacts   = 100
)

// Effective returns l with any zero field replaced by its default.
func (l Limits) Effective() Limits {
	if l.MaxFactsPerType <= 0 {
		l.MaxFactsPerType = DefaultMaxFactsPerType
	}
	if l.MaxTotalFacts <= 0 {
		l.MaxTotalFacts = DefaultMaxTotalFacts
	}
	return l
}

// Truncate deterministically bounds facts to l's limits (phase13.md §13):
// facts are first sorted newest-first within each type (a recency bias —
// the most recent evidence is the most likely to matter to an active
// investigation), then each type is capped at MaxFactsPerType, then the
// overall list is capped at MaxTotalFacts (again newest-first across
// types). The same input always produces the same output — no
// randomness, no map-iteration-order dependence (phase13.md §69's
// determinism requirement).
func Truncate(facts []Fact, limits Limits) (kept []Fact, truncated bool) {
	limits = limits.Effective()

	byType := make(map[FactType][]Fact)
	var order []FactType
	for _, f := range facts {
		if _, seen := byType[f.Type]; !seen {
			order = append(order, f.Type)
		}
		byType[f.Type] = append(byType[f.Type], f)
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })

	var perTypeKept []Fact
	for _, t := range order {
		group := byType[t]
		sort.SliceStable(group, func(i, j int) bool { return group[i].Timestamp.After(group[j].Timestamp) })
		if len(group) > limits.MaxFactsPerType {
			truncated = true
			group = group[:limits.MaxFactsPerType]
		}
		perTypeKept = append(perTypeKept, group...)
	}

	sort.SliceStable(perTypeKept, func(i, j int) bool { return perTypeKept[i].Timestamp.After(perTypeKept[j].Timestamp) })
	if len(perTypeKept) > limits.MaxTotalFacts {
		truncated = true
		perTypeKept = perTypeKept[:limits.MaxTotalFacts]
	}

	// Restore chronological (oldest-first) order for presentation — the
	// truncation decision above is recency-biased, but a timeline/summary
	// should read chronologically once the cut has been made.
	sort.SliceStable(perTypeKept, func(i, j int) bool { return perTypeKept[i].Timestamp.Before(perTypeKept[j].Timestamp) })

	return perTypeKept, truncated
}

// TruncationNote is the exact, explicit warning phase13.md §13 requires be
// told to the model whenever Truncate reports truncated=true.
const TruncationNote = "Some evidence was omitted because of context limits."
