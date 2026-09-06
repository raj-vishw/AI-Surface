package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"

	"github.com/google/uuid"
)

// ComputeFingerprint returns component's deduplication key (phase12.md
// §27): targetID plus every node's stable (Type, ReferenceID) identity,
// sorted for order-independence, plus windowStart truncated onto
// windowDuration's own grid — the same "truncate onto the window's own
// grid so repeated evaluation collapses to one fingerprint" approach
// internal/ruleengine.ComputeFingerprint uses for Phase 11's detection
// matches. Re-evaluating the identical underlying node set within the
// same window always yields the same fingerprint, so
// internal/repository/correlation's upsert can widen LastObservedAt on
// the existing row instead of creating a duplicate (phase12.md §28).
func ComputeFingerprint(targetID uuid.UUID, component Graph, windowStart time.Time, windowDuration time.Duration) string {
	keys := make([]string, 0, len(component.Nodes))
	for _, n := range component.Nodes {
		keys = append(keys, n.Ref.Key())
	}
	sort.Strings(keys)

	bucket := windowStart
	if windowDuration > 0 {
		bucket = windowStart.Truncate(windowDuration)
	}

	h := sha256.New()
	h.Write([]byte(targetID.String())) //nolint:errcheck // hash.Hash.Write never errors
	for _, k := range keys {
		h.Write([]byte("|" + k)) //nolint:errcheck
	}
	h.Write([]byte("|" + bucket.UTC().Format(time.RFC3339))) //nolint:errcheck
	return hex.EncodeToString(h.Sum(nil))
}
