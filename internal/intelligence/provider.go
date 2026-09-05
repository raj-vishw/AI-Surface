package intelligence

import (
	"context"
	"fmt"
)

// Provider looks up intelligence for one Indicator. Implementations must
// respect ctx's deadline/cancellation and must never block the pipeline
// indefinitely (phase10.md §69) — a network-backed provider bounds its
// own request timeout and response size internally (see providers/
// threat_feed.go).
type Provider interface {
	ID() string
	Name() string
	// Version identifies this provider's current behavior — recorded on
	// every Record it produces (phase10.md §6) so a historical record
	// remains interpretable if the provider's logic later changes.
	Version() string
	Capabilities() []Capability
	Lookup(ctx context.Context, indicator Indicator) ([]Record, error)
}

// ProviderError is one provider's failure during an Engine.Lookup call —
// a provider failing must never abort the rest of the lookup (phase10.md
// §25).
type ProviderError struct {
	ProviderID string
	Err        error
}

func (e ProviderError) Error() string {
	return fmt.Sprintf("provider %s: %v", e.ProviderID, e.Err)
}
