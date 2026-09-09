// Package endpoint implements the endpoint & API discovery engine (Phase
// 7): bounded crawling, HTML/JavaScript static extraction, robots.txt/
// sitemap.xml parsing, OpenAPI/Swagger parsing, and endpoint
// classification. It analyzes only URLs it fetches itself (GET only —
// never PUT/PATCH/DELETE merely to discover, phase7.md §30) or that it
// finds passively in already-fetched content; it is an inventory engine,
// not a vulnerability scanner (phase7.md §3/§90). It persists nothing —
// internal/discovery/service normalizes results into Phase 2 assets/
// endpoints/evidence, exactly the split every other discovery engine in
// this project already follows.
package endpoint

import (
	"fmt"
	"time"

	"ai-surface-platform/internal/config"
)

// Config is the endpoint discovery engine's resolved configuration — the
// same shape as config.EndpointDiscoveryConfig (this package does not
// define a second configuration system; see FromAppConfig).
type Config struct {
	Timeout           time.Duration
	MaxConcurrency    int
	RequestsPerSecond float64
	MaxResponseSize   int64

	MaxDepth     int
	MaxPages     int
	MaxEndpoints int

	FollowRedirects bool
	MaxRedirects    int

	EnableRobots     bool
	EnableSitemap    bool
	EnableJavaScript bool
	EnableOpenAPI    bool

	MaxSitemaps    int
	MaxSitemapURLs int

	SeedPaths           []string
	SensitiveParameters []string

	Profiles map[string]config.EndpointProfileConfig
}

// FromAppConfig builds a discovery Config from the application's
// discovery.endpoint configuration section.
func FromAppConfig(cfg config.EndpointDiscoveryConfig) Config {
	return Config{
		Timeout: cfg.Timeout, MaxConcurrency: cfg.MaxConcurrency, RequestsPerSecond: cfg.RequestsPerSecond,
		MaxResponseSize: cfg.MaxResponseSize,
		MaxDepth:        cfg.MaxDepth, MaxPages: cfg.MaxPages, MaxEndpoints: cfg.MaxEndpoints,
		FollowRedirects: cfg.FollowRedirects, MaxRedirects: cfg.MaxRedirects,
		EnableRobots: cfg.EnableRobots, EnableSitemap: cfg.EnableSitemap,
		EnableJavaScript: cfg.EnableJavaScript, EnableOpenAPI: cfg.EnableOpenAPI,
		MaxSitemaps: cfg.MaxSitemaps, MaxSitemapURLs: cfg.MaxSitemapURLs,
		SeedPaths: cfg.SeedPaths, SensitiveParameters: cfg.SensitiveParameters,
		Profiles: cfg.Profiles,
	}
}

// ResolveProfile applies a named profile's overrides on top of c's base
// values — 0/false fields in the profile inherit the base (the same
// "0 means inherit" convention dns.Config.ResolveProfile established).
// An empty profile name returns c unchanged.
func (c Config) ResolveProfile(profile string) (Config, error) {
	if profile == "" {
		return c, nil
	}
	p, ok := c.Profiles[profile]
	if !ok {
		return Config{}, fmt.Errorf("unknown endpoint discovery profile %q", profile)
	}
	resolved := c
	if p.MaxDepth > 0 {
		resolved.MaxDepth = p.MaxDepth
	}
	if p.MaxPages > 0 {
		resolved.MaxPages = p.MaxPages
	}
	if p.MaxEndpoints > 0 {
		resolved.MaxEndpoints = p.MaxEndpoints
	}
	resolved.EnableRobots = p.EnableRobots
	resolved.EnableSitemap = p.EnableSitemap
	resolved.EnableJavaScript = p.EnableJavaScript
	resolved.EnableOpenAPI = p.EnableOpenAPI
	return resolved, nil
}
