package reporting

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// ContentHash computes a SHA-256 hash of content (phase14.md §41's
// report integrity hash) — used only for later verification that a
// report row was not modified outside this platform's own write path,
// never as an authentication mechanism (the same limitation phase14.md
// §47 states explicitly for evidence-item hashes).
func ContentHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// ItemHash computes one evidence item's integrity hash (phase14.md §47)
// from its own stable identity — never from mutable display text, so
// the hash is reproducible from the same underlying evidence regardless
// of when the manifest is regenerated.
func ItemHash(itemType, referenceID string, timestamp time.Time) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{itemType, referenceID, timestamp.UTC().Format(time.RFC3339Nano)}, "|")))
	return hex.EncodeToString(sum[:])
}
