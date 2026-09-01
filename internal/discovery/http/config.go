// Package http implements the HTTP discovery engine: deterministic
// candidate URL generation, scope enforcement, bounded-concurrency request
// execution over the Phase 1 HTTP client, response analysis, and AI
// endpoint candidate detection. It does not persist anything — see
// internal/discovery/service for the layer that normalizes Results into
// Phase 2 assets/endpoints/evidence.
package http

import (
	"fmt"
	"time"

	"ai-recon-platform/internal/config"
)

// Config is the HTTP discovery engine's resolved configuration — the same
// shape as config.HTTPDiscoveryConfig (this package does not define a
// second configuration system; see FromAppConfig).
type Config struct {
	Timeout           time.Duration
	MaxConcurrency    int
	MaxResponseSize   int64
	FollowRedirects   bool
	MaxRedirects      int
	Methods           []string
	Schemes           []string
	Paths             []string
	DetectAIEndpoints bool
	Profiles          map[string]config.ProfileConfig
}

// FromAppConfig builds a discovery Config from the application's
// discovery.http configuration section.
func FromAppConfig(cfg config.HTTPDiscoveryConfig) Config {
	return Config{
		Timeout:           cfg.Timeout,
		MaxConcurrency:    cfg.MaxConcurrency,
		MaxResponseSize:   cfg.MaxResponseSize,
		FollowRedirects:   cfg.FollowRedirects,
		MaxRedirects:      cfg.MaxRedirects,
		Methods:           cfg.Methods,
		Schemes:           cfg.Schemes,
		Paths:             cfg.Paths,
		DetectAIEndpoints: cfg.DetectAIEndpoints,
		Profiles:          cfg.Profiles,
	}
}

// ResolvePaths returns the path list a scan should use: profile's paths if
// profile is non-empty and recognized, otherwise c.Paths (the full
// configured set — the "comprehensive" behavior when no profile is named).
// Profiles are entirely data (loaded from configuration), never
// hard-coded path lists in this function — see config.ProfileConfig.
func (c Config) ResolvePaths(profile string) ([]string, error) {
	if profile == "" {
		return c.Paths, nil
	}
	p, ok := c.Profiles[profile]
	if !ok {
		return nil, fmt.Errorf("unknown discovery profile %q", profile)
	}
	return p.Paths, nil
}
