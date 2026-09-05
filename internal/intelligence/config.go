package intelligence

import "time"

// DefaultReputationTTL/DefaultVulnerabilityTTL are the built-in cache
// TTLs (phase10.md §22's worked example) used when Config doesn't
// override them.
const (
	DefaultReputationTTL    = 24 * time.Hour
	DefaultVulnerabilityTTL = 7 * 24 * time.Hour
)

// DefaultProviderTimeout bounds a single provider's Lookup call
// (phase10.md §69).
const DefaultProviderTimeout = 10 * time.Second

// Config configures one Engine.Lookup run. It carries no database detail
// — internal/service/intelligence resolves configuration
// (internal/config.IntelligenceConfig) into this shape, the same split
// internal/investigation.Config uses.
type Config struct {
	// Providers maps a provider id to enabled/disabled — absent means
	// enabled, the same "closed set of explicit opt-outs" convention
	// detection.Config.Detectors/investigation.Config.Rules use.
	Providers map[string]bool
	// ProviderTimeout bounds each individual provider's Lookup call.
	// <= 0 uses DefaultProviderTimeout.
	ProviderTimeout time.Duration
	// ReputationTTL/VulnerabilityTTL are the cache TTLs applied when
	// persisting a reputation/vulnerability-catalog-sourced record. <= 0
	// uses the package Default* constants.
	ReputationTTL    time.Duration
	VulnerabilityTTL time.Duration
	// ExternalEnrichmentEnabled gates every provider whose Capabilities()
	// includes CapabilityThreatFeed (phase10.md §29/§30/§73) — false by
	// default (phase10.md §29's "default should be conservative").
	ExternalEnrichmentEnabled bool
	Weights                   SourceWeights
}

// ProviderEnabled reports whether id is enabled under c.
func (c Config) ProviderEnabled(id string) bool {
	if c.Providers == nil {
		return true
	}
	enabled, ok := c.Providers[id]
	if !ok {
		return true
	}
	return enabled
}

// EffectiveProviderTimeout returns c's effective ProviderTimeout.
func (c Config) EffectiveProviderTimeout() time.Duration {
	if c.ProviderTimeout <= 0 {
		return DefaultProviderTimeout
	}
	return c.ProviderTimeout
}

// EffectiveReputationTTL returns c's effective ReputationTTL.
func (c Config) EffectiveReputationTTL() time.Duration {
	if c.ReputationTTL <= 0 {
		return DefaultReputationTTL
	}
	return c.ReputationTTL
}

// EffectiveVulnerabilityTTL returns c's effective VulnerabilityTTL.
func (c Config) EffectiveVulnerabilityTTL() time.Duration {
	if c.VulnerabilityTTL <= 0 {
		return DefaultVulnerabilityTTL
	}
	return c.VulnerabilityTTL
}
