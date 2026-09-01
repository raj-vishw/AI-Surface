package dns

import (
	"fmt"
	"time"

	"ai-recon-platform/internal/config"
)

// SubdomainConfig configures subdomain enumeration — kept as its own
// struct, separate from record-type discovery settings, so the two
// concepts are never mixed (phase5.md §1).
type SubdomainConfig struct {
	Enabled           bool
	MaxCandidates     int
	Wordlist          string
	Words             []string
	WildcardDetection bool
	MaxDepth          int
}

// Config is the DNS discovery engine's resolved configuration — the same
// shape as config.DNSDiscoveryConfig (this package does not define a
// second configuration system; see FromAppConfig).
type Config struct {
	Timeout           time.Duration
	MaxConcurrency    int
	Resolvers         []string
	RecordTypes       []RecordType
	ReversePTR        bool
	RequestsPerSecond float64
	Subdomains        SubdomainConfig
	Profiles          map[string]config.DNSProfileConfig
}

// FromAppConfig builds a discovery Config from the application's
// discovery.dns configuration section.
func FromAppConfig(cfg config.DNSDiscoveryConfig) Config {
	types := make([]RecordType, len(cfg.RecordTypes))
	for i, t := range cfg.RecordTypes {
		types[i] = RecordType(t)
	}
	return Config{
		Timeout:           cfg.Timeout,
		MaxConcurrency:    cfg.MaxConcurrency,
		Resolvers:         cfg.Resolvers,
		RecordTypes:       types,
		ReversePTR:        cfg.ReversePTR,
		RequestsPerSecond: cfg.RequestsPerSecond,
		Subdomains: SubdomainConfig{
			Enabled:           cfg.Subdomains.Enabled,
			MaxCandidates:     cfg.Subdomains.MaxCandidates,
			Wordlist:          cfg.Subdomains.Wordlist,
			Words:             cfg.Subdomains.Words,
			WildcardDetection: cfg.Subdomains.WildcardDetection,
			MaxDepth:          cfg.Subdomains.MaxDepth,
		},
		Profiles: cfg.Profiles,
	}
}

// ResolveProfile returns the record types, subdomain words, and subdomain
// max depth a named profile selects. Empty profile returns c's own
// RecordTypes, Subdomains.Words, and Subdomains.MaxDepth directly (no
// profile requested — use the base configuration as-is). maxDepth is
// always resolved (never 0) — a profile with no MaxDepth override falls
// back to c.Subdomains.MaxDepth, the same "0 means inherit" rule
// config.DNSProfileConfig.MaxDepth documents.
func (c Config) ResolveProfile(profile string) (recordTypes []RecordType, subdomainWords []string, maxDepth int, err error) {
	if profile == "" {
		return c.RecordTypes, c.Subdomains.Words, c.Subdomains.MaxDepth, nil
	}
	p, ok := c.Profiles[profile]
	if !ok {
		return nil, nil, 0, fmt.Errorf("unknown DNS profile %q", profile)
	}
	types := make([]RecordType, len(p.RecordTypes))
	for i, t := range p.RecordTypes {
		types[i] = RecordType(t)
	}
	depth := p.MaxDepth
	if depth == 0 {
		depth = c.Subdomains.MaxDepth
	}
	return types, p.SubdomainWords, depth, nil
}
