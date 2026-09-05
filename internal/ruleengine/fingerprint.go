package ruleengine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

// ComputeFingerprint returns the deduplication key for a match
// (phase11.md §33): rule ID + rule version + the relevant group keys +
// a normalized time window — never an unstable value like a random UUID
// or a raw (sub-window-precision) timestamp, so re-evaluating the same
// underlying pattern within the same window produces the identical
// fingerprint. windowDuration truncates windowStart onto a fixed grid
// (windowStart.Truncate(windowDuration)) so two evaluations of
// overlapping-but-not-identical windows over the same events still
// collapse to one fingerprint, exactly as phase11.md §33 requires.
func ComputeFingerprint(ruleID uuid.UUID, ruleVersion int, groupKey map[string]string, windowStart time.Time, windowDuration time.Duration) string {
	bucket := windowStart.UTC()
	if windowDuration > 0 {
		bucket = bucket.Truncate(windowDuration)
	}

	keys := make([]string, 0, len(groupKey))
	for k := range groupKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()                                                                     // hash.Hash.Write never returns an error
	fmt.Fprintf(h, "%s|%d|%s", ruleID.String(), ruleVersion, bucket.Format(time.RFC3339)) //nolint:errcheck
	for _, k := range keys {
		fmt.Fprintf(h, "|%s=%s", k, groupKey[k]) //nolint:errcheck
	}
	return hex.EncodeToString(h.Sum(nil))
}
