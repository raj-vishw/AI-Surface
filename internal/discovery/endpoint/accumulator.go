package endpoint

import (
	"sort"
	"strings"
	"sync"
)

// accumulator merges every contribution (from crawling, robots.txt,
// sitemap.xml, JavaScript, OpenAPI/Swagger) into one logical Result per
// (method, normalized URL) identity — phase7.md §39/§40: "/api/users
// found through HTML, JavaScript, and OpenAPI... one endpoint with
// sources: [html, javascript, openapi]", never three separate rows.
// Safe for concurrent use.
type accumulator struct {
	mu           sync.Mutex
	byKey        map[string]*Result
	order        []string
	maxEndpoints int
}

func newAccumulator(maxEndpoints int) *accumulator {
	return &accumulator{byKey: make(map[string]*Result), maxEndpoints: maxEndpoints}
}

func resultKey(method, url string) string { return method + " " + url }

// Full reports whether the accumulator has reached its configured
// endpoint ceiling (phase7.md §24 — "never crawl indefinitely" applied to
// the endpoint count, not just page count).
func (a *accumulator) Full() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.byKey) >= a.maxEndpoints
}

// Add merges r into the accumulator by its (Method, URL) identity — a new
// key is only added if the accumulator has not yet reached maxEndpoints
// (a key already present is always allowed to merge further contributions
// even once "full", since that's corroboration of an existing endpoint,
// not a new one).
func (a *accumulator) Add(r Result) {
	key := resultKey(r.Method, r.URL)
	a.mu.Lock()
	defer a.mu.Unlock()

	existing, ok := a.byKey[key]
	if !ok {
		if len(a.byKey) >= a.maxEndpoints {
			return
		}
		cp := r
		a.byKey[key] = &cp
		a.order = append(a.order, key)
		return
	}
	mergeInto(existing, r)
}

// mergeInto folds new's contribution into existing — corroboration
// (multiple sources) accumulates, confidence takes the higher value,
// documented/observed/inferred are monotonic OR, and an actual
// observation's concrete fields (status code, content type, ...) always
// win over a merely-documented/inferred placeholder's absence of them.
func mergeInto(existing *Result, add Result) {
	existing.Sources = mergeStrings(existing.Sources, add.Sources)
	existing.QueryPattern = mergeQueryPattern(existing.QueryPattern, add.QueryPattern)
	if add.Confidence > existing.Confidence {
		existing.Confidence = add.Confidence
	}
	existing.Documented = existing.Documented || add.Documented
	existing.Observed = existing.Observed || add.Observed
	existing.Inferred = existing.Inferred || add.Inferred
	existing.Truncated = existing.Truncated || add.Truncated

	if add.StatusCode != nil {
		existing.StatusCode = add.StatusCode
	}
	if add.ContentType != "" {
		existing.ContentType = add.ContentType
	}
	if add.ContentLength != nil {
		existing.ContentLength = add.ContentLength
	}
	if add.ResponseHash != "" {
		existing.ResponseHash = add.ResponseHash
	}
	if add.Classification != "" && add.Classification != ClassUnknown {
		existing.Classification = add.Classification
	}
	if add.APIType != "" {
		existing.APIType = add.APIType
	}
	if add.APIVersion != "" {
		existing.APIVersion = add.APIVersion
	}
	if add.Error != "" {
		existing.Error = add.Error
	}
	if add.ObservedAt.After(existing.ObservedAt) {
		existing.ObservedAt = add.ObservedAt
	}

	existing.Parameters = mergeParameters(existing.Parameters, add.Parameters)

	if existing.Evidence == nil {
		existing.Evidence = map[string]string{}
	}
	for k, v := range add.Evidence {
		if _, already := existing.Evidence[k]; !already {
			existing.Evidence[k] = v
		}
	}
}

// mergeQueryPattern unions two comma-joined, sorted parameter-name lists
// (internal/domain/endpoint.Normalize's QueryPattern shape) — e.g. one
// observation of "/search?q=x" and another of "/search?q=x&page=2" must
// still report both "page" and "q" as parameters this endpoint accepts,
// never just whichever contribution happened to be recorded first.
func mergeQueryPattern(existing, add string) string {
	if existing == "" {
		return add
	}
	if add == "" {
		return existing
	}
	return joinSortedUnique(strings.Split(existing, ","), strings.Split(add, ","))
}

func joinSortedUnique(a, b []string) string {
	seen := make(map[string]bool, len(a)+len(b))
	var names []string
	for _, n := range append(append([]string{}, a...), b...) {
		if n != "" && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

func mergeStrings(existing, add []string) []string {
	seen := make(map[string]bool, len(existing))
	out := append([]string(nil), existing...)
	for _, s := range existing {
		seen[s] = true
	}
	for _, s := range add {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func mergeParameters(existing, add []Parameter) []Parameter {
	seen := make(map[string]bool, len(existing))
	out := append([]Parameter(nil), existing...)
	for _, p := range existing {
		seen[p.Name+"|"+p.Location] = true
	}
	for _, p := range add {
		key := p.Name + "|" + p.Location
		if !seen[key] {
			seen[key] = true
			out = append(out, p)
		}
	}
	return out
}

// results returns every accumulated Result, in the deterministic order
// keys were first added.
func (a *accumulator) results() []Result {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Result, 0, len(a.order))
	for _, k := range a.order {
		out = append(out, *a.byKey[k])
	}
	return out
}
