package dns

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// CandidateSource records where a SubdomainCandidate came from
// (phase5.md §21). Phase 5 uses "wordlist" and "dns_record" (a name
// observed in another record's value — a CNAME/MX/NS target, for
// instance — re-queried in its own right); "passive"/"certificate"/
// "manual" are reserved vocabulary for later phases, not built here (no
// certificate-transparency integration exists in this phase — phase5.md
// §21/§45).
type CandidateSource string

// Recognized candidate sources.
const (
	SourceWordlist    CandidateSource = "wordlist"
	SourceDNSRecord   CandidateSource = "dns_record"
	SourcePassive     CandidateSource = "passive"
	SourceCertificate CandidateSource = "certificate"
	SourceManual      CandidateSource = "manual"
)

// SubdomainCandidate is a name to attempt resolving — not yet a
// discovered subdomain; discovery requires DNS evidence (see
// classifier.go / scanner.go), never mere presence in a wordlist
// (phase5.md §26).
type SubdomainCandidate struct {
	Name       string
	Source     CandidateSource
	Confidence float64
	ObservedAt time.Time
}

// LoadWordlist reads newline-delimited candidate labels from path,
// skipping blank lines and "#"-prefixed comments.
func LoadWordlist(path string) ([]string, error) {
	f, err := os.Open(path) //nolint:gosec // path is an operator-supplied --wordlist/config value, not external/user input
	if err != nil {
		return nil, fmt.Errorf("opening wordlist %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var words []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		words = append(words, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading wordlist %q: %w", path, err)
	}
	return words, nil
}

// GenerateCandidates deterministically builds the deduplicated subdomain
// candidate list for domain from words, up to maxDepth label-combination
// levels, capped at maxCandidates (phase5.md §22/§23/§24/§25):
//
//   - depth 1: "<word>.<domain>" for every word
//   - depth 2: "<word>.<word>.<domain>" for every ordered pair — never
//     unlimited recursive combination; depth is a hard, small ceiling
//   - every candidate is normalized (NormalizeName) and deduplicated
//     against that normalized form before counting toward maxCandidates,
//     so "API.example.test" and "api.example.test." collapse to one
//     candidate, consuming the budget once, not twice
//
// Output is sorted for determinism. If the combination space would exceed
// maxCandidates, generation stops deterministically (always the same
// prefix of candidates, in the same order) rather than sampling randomly.
func GenerateCandidates(domain string, words []string, maxDepth, maxCandidates int) ([]SubdomainCandidate, error) {
	normalizedDomain, err := NormalizeName(domain)
	if err != nil {
		return nil, fmt.Errorf("invalid domain %q: %w", domain, err)
	}
	if maxDepth < 1 {
		maxDepth = 1
	}

	cleanWords := normalizeWords(words)
	if len(cleanWords) == 0 {
		return nil, nil
	}

	seen := make(map[string]bool)
	var names []string

	addName := func(name string) bool {
		normalized, err := NormalizeName(name)
		if err != nil {
			return len(names) < maxCandidates // skip invalid combinations silently, keep going
		}
		if seen[normalized] {
			return len(names) < maxCandidates
		}
		seen[normalized] = true
		names = append(names, normalized)
		return len(names) < maxCandidates
	}

	// Depth 1: every word directly under domain.
	for _, w := range cleanWords {
		if !addName(JoinLabel(w, normalizedDomain)) {
			break
		}
	}

	// Depth 2..maxDepth: combine words onto the previous depth's names —
	// bounded to maxDepth levels and maxCandidates total, never unbounded
	// recursive expansion (phase5.md §24).
	depthStart := 0
	for depth := 2; depth <= maxDepth && len(names) < maxCandidates; depth++ {
		depthNames := names[depthStart:]
		depthStart = len(names)
		for _, base := range depthNames {
			done := false
			for _, w := range cleanWords {
				if !addName(JoinLabel(w, base)) {
					done = true
					break
				}
			}
			if done {
				break
			}
		}
	}

	sort.Strings(names)

	candidates := make([]SubdomainCandidate, len(names))
	now := time.Now().UTC()
	for i, n := range names {
		candidates[i] = SubdomainCandidate{Name: n, Source: SourceWordlist, Confidence: 1.0, ObservedAt: now}
	}
	return candidates, nil
}

func normalizeWords(words []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, w := range words {
		w = strings.ToLower(strings.TrimSpace(w))
		if w == "" || seen[w] {
			continue
		}
		seen[w] = true
		out = append(out, w)
	}
	return out
}
