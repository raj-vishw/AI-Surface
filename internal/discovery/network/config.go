package network

import (
	"fmt"
	"time"

	"ai-surface-platform/internal/config"
)

// Config is the network discovery engine's resolved configuration — the
// same shape as config.NetworkDiscoveryConfig (this package does not
// define a second configuration system; see FromAppConfig).
type Config struct {
	ConnectTimeout     time.Duration
	MaxConcurrency     int
	MaxHosts           int
	RequestsPerSecond  float64
	HTTPCandidatePorts []int
	AICandidatePorts   []int
	Profiles           map[string]config.NetworkProfileConfig
}

// FromAppConfig builds a discovery Config from the application's
// discovery.network configuration section.
func FromAppConfig(cfg config.NetworkDiscoveryConfig) Config {
	return Config{
		ConnectTimeout:     cfg.ConnectTimeout,
		MaxConcurrency:     cfg.MaxConcurrency,
		MaxHosts:           cfg.MaxHosts,
		RequestsPerSecond:  cfg.RequestsPerSecond,
		HTTPCandidatePorts: cfg.HTTPCandidatePorts,
		AICandidatePorts:   cfg.AICandidatePorts,
		Profiles:           cfg.Profiles,
	}
}

// ResolvePorts returns the port list a scan should use: profile's ports
// if profile is non-empty and recognized, otherwise nil (the caller —
// cmd/cli — is responsible for requiring either a profile or an explicit
// --ports value; unlike HTTP discovery, network discovery has no single
// "full configured set" fallback, since scanning literally every profile's
// ports combined would silently expand scope beyond what was asked for).
func (c Config) ResolvePorts(profile string) ([]int, error) {
	if profile == "" {
		return nil, nil
	}
	p, ok := c.Profiles[profile]
	if !ok {
		return nil, fmt.Errorf("unknown network profile %q", profile)
	}
	return p.Ports, nil
}
