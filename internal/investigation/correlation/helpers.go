// Package correlation implements Phase 9's built-in correlation Rule set
// (phase9.md §12-21) and RegisterAll, which registers every one of them
// into an internal/investigation.Registry — the same split
// internal/detection/detectors is for internal/detection (phase8.md §1,
// reused for phase9.md §14).
package correlation

import (
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/investigation"
)

// explanation joins a base sentence with the concrete evidence, e.g.
// "Both findings affect the same asset (example.test)." — never a bare
// "related: true" (phase9.md §35).
func explanation(base string, detail string) string {
	if detail == "" {
		return base
	}
	return base + " " + detail
}

// newRelationship builds a finding-to-finding Relationship — the shape
// every rule in this package produces (phase9.md §12's relationships are
// all finding-pair relationships).
func newRelationship(a, b investigation.FindingObservation, relType investigation.RelationshipType, score int, signal string, explain string) investigation.Relationship {
	return investigation.Relationship{
		SourceType: investigation.EntityFinding, SourceID: a.ID,
		TargetType: investigation.EntityFinding, TargetID: b.ID,
		Type: relType, Score: score, Signals: map[string]int{signal: score},
		Explanation: explain,
	}
}

// withinWindow reports whether t1 and t2 fall within window of each
// other, in either direction.
func withinWindow(t1, t2 time.Time, window time.Duration) bool {
	if t1.IsZero() || t2.IsZero() {
		return false
	}
	diff := t1.Sub(t2)
	if diff < 0 {
		diff = -diff
	}
	return diff <= window
}

// newEntityRelationship builds a Finding-to-other-entity Relationship
// (asset/endpoint/technology) — used by rules that correlate a finding
// with something other than another finding (phase9.md §19/§20/§21).
func newEntityRelationship(finding investigation.FindingObservation, targetType investigation.EntityType, targetID uuid.UUID, relType investigation.RelationshipType, score int, signal string, explain string) investigation.Relationship {
	return investigation.Relationship{
		SourceType: investigation.EntityFinding, SourceID: finding.ID,
		TargetType: targetType, TargetID: targetID,
		Type: relType, Score: score, Signals: map[string]int{signal: score},
		Explanation: explain,
	}
}

// forEachFindingPair calls fn once for every distinct unordered pair of
// findings in fs — the O(n^2) iteration every pairwise correlation rule
// in this package needs, factored out so each rule's own file states only
// its actual condition.
func forEachFindingPair(fs []investigation.FindingObservation, fn func(a, b investigation.FindingObservation)) {
	for i := range fs {
		for j := i + 1; j < len(fs); j++ {
			fn(fs[i], fs[j])
		}
	}
}
