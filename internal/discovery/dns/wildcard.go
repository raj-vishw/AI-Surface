package dns

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

// probeCount is how many randomized labels are resolved to establish a
// wildcard baseline (phase5.md §29) — multiple probes, not one, so a
// single coincidental resolution doesn't produce a false wildcard
// conclusion.
const probeCount = 3

// WildcardDetection is the outcome of probing domain for wildcard DNS
// (phase5.md §30).
type WildcardDetection struct {
	Domain     string
	Detected   bool
	RecordSet  []string // sorted, normalized values shared by every probe (only set when Detected)
	ObservedAt time.Time
	Confidence float64
}

// DetectWildcard resolves probeCount randomized, near-certainly-unused
// labels under domain and checks whether they all resolve to the same
// non-empty record set. If so, that record set is the wildcard baseline —
// see MatchesWildcard for how real candidates are evaluated against it.
// No asset is ever created for the random probe names themselves
// (phase5.md §30) — DetectWildcard only returns a detection result, never
// a Record or asset-shaped value for the probes.
func DetectWildcard(ctx context.Context, resolver Resolver, domain string, recordTypes []RecordType) (WildcardDetection, error) {
	detection := WildcardDetection{Domain: domain, ObservedAt: time.Now().UTC()}

	var probeResultSets [][]string
	for i := 0; i < probeCount; i++ {
		label, err := randomLabel()
		if err != nil {
			return WildcardDetection{}, fmt.Errorf("generating random probe label: %w", err)
		}
		name := JoinLabel(label, domain)

		values, resolved := resolveAny(ctx, resolver, name, recordTypes)
		if !resolved {
			// Any probe failing to resolve at all means there is no
			// consistent wildcard behavior — stop early, no wildcard.
			return detection, nil
		}
		probeResultSets = append(probeResultSets, values)
	}

	baseline := probeResultSets[0]
	for _, set := range probeResultSets[1:] {
		if !sameSet(baseline, set) {
			return detection, nil // inconsistent results across probes: not a wildcard
		}
	}

	detection.Detected = true
	detection.RecordSet = baseline
	detection.Confidence = 1.0
	return detection, nil
}

// resolveAny queries every recordType for name (in order) and returns the
// sorted, normalized values of the first type that resolves successfully,
// plus whether anything resolved at all.
func resolveAny(ctx context.Context, resolver Resolver, name string, recordTypes []RecordType) ([]string, bool) {
	for _, rt := range recordTypes {
		result, err := resolver.Lookup(ctx, name, rt)
		if err != nil {
			continue
		}
		if classify(result) != StateResolved {
			continue
		}
		values := make([]string, len(result.Records))
		for i, r := range result.Records {
			values[i] = r.Value
		}
		sort.Strings(values)
		return values, true
	}
	return nil, false
}

// MatchesWildcard reports whether values (a resolved candidate's sorted
// record values) is indistinguishable from detection's wildcard baseline.
// A candidate whose result differs from the baseline is still a genuine,
// independently-discovered record even under a wildcard domain
// (phase5.md §29/§58) — this function is how that distinction is made.
func (d WildcardDetection) MatchesWildcard(values []string) bool {
	if !d.Detected {
		return false
	}
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	return sameSet(d.RecordSet, sorted)
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func randomLabel() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "wc-" + hex.EncodeToString(buf), nil
}
