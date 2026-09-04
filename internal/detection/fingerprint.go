package detection

import "github.com/google/uuid"

// IdentityKey returns the deterministic grouping key two Finding values
// share when they represent the same logical finding (phase8.md §3):
// never a timestamp, random UUID, or scan id — only asset, an optional
// endpoint, and the detector that produced it. This is the engine-side
// counterpart of internal/domain/finding.IdentityKey, computed
// independently to keep this package free of a domain-layer dependency
// (the same split internal/fingerprint keeps from internal/domain/
// fingerprint).
func IdentityKey(assetID uuid.UUID, endpointID *uuid.UUID, detectorID string) string {
	key := assetID.String() + "|" + detectorID
	if endpointID != nil {
		key += "|" + endpointID.String()
	}
	return key
}
