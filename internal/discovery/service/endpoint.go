// Package service orchestrates discovery end-to-end. This file adds
// endpoint & API discovery orchestration (Phase 7) to the same package
// as discovery.go (Phase 3), network.go (Phase 4), and dns.go (Phase 5)
// — one Service, the same authorization -> scope -> scan -> persist
// shape, never a parallel orchestrator.
package service

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"

	discoveryendpoint "ai-surface-platform/internal/discovery/endpoint"
	discoveryhttp "ai-surface-platform/internal/discovery/http"
	domainasset "ai-surface-platform/internal/domain/asset"
	domainendpoint "ai-surface-platform/internal/domain/endpoint"
	domaintarget "ai-surface-platform/internal/domain/target"
	apperrors "ai-surface-platform/internal/errors"
	assetrepo "ai-surface-platform/internal/repository/asset"
	"ai-surface-platform/internal/repository/pagination"
)

// endpointSource is the fixed evidence/asset Source attribution for
// everything this file persists — distinct from "http"/"network"/"dns"/
// "fingerprint", so every asset stays attributable to the discovery pass
// that found it.
const endpointSource = "endpoint"

// supportedEndpointTargetTypes are the target types Phase 7 accepts —
// the same URL/HOST/DOMAIN set Phase 3's HTTP discovery accepts, since
// endpoint discovery is fundamentally the same "start from a web-facing
// target" concept, extended with crawling.
var supportedEndpointTargetTypes = map[domaintarget.Type]bool{
	domaintarget.TypeURL: true, domaintarget.TypeHost: true, domaintarget.TypeDomain: true,
}

// EndpointRequest describes one `ai-surface endpoint-scan` invocation.
type EndpointRequest struct {
	TargetType  domaintarget.Type
	TargetValue string
	Profile     string
	// SeedURLs, if non-empty, are used INSTEAD of the seeds normally
	// derived from the target's own known HTTP(S) assets (phase7.md
	// §58's --seed flag) — explicitly supplied seeds still go through
	// scope validation like any other candidate.
	SeedURLs []string
	DryRun   bool
	Config   discoveryendpoint.Config
}

// EndpointDryRunReport is returned instead of a Summary when req.DryRun
// is true — no HTTP request is made and nothing is persisted (phase7.md
// §60).
type EndpointDryRunReport struct {
	Target       string
	Seeds        []string
	MaxDepth     int
	MaxPages     int
	MaxEndpoints int
	Sources      []string
}

// RunEndpoint loads and authorizes req's target, then either reports the
// crawl plan (EndpointDryRunReport) or executes the crawl and persists
// every result through AssetService (*discoveryendpoint.Summary), also
// returning the Changes detected relative to the target's previous
// endpoint state. Exactly one of the two return values is non-nil on
// success.
func (s *Service) RunEndpoint(ctx context.Context, req EndpointRequest) (*discoveryendpoint.Summary, *EndpointDryRunReport, []EndpointChange, error) {
	if !supportedEndpointTargetTypes[req.TargetType] {
		return nil, nil, nil, apperrors.NewValidation(
			fmt.Sprintf("target type %s is not supported by endpoint discovery (only URL, HOST, DOMAIN)", req.TargetType), nil)
	}

	target, err := s.targets.GetByValue(ctx, req.TargetType, req.TargetValue)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading target: %w", err)
	}
	if err := target.Validate(); err != nil {
		return nil, nil, nil, fmt.Errorf("target is invalid: %w", err)
	}
	if !target.IsAuthorized() {
		return nil, nil, nil, apperrors.NewForbidden("target is not authorized for active discovery", nil)
	}

	cfg, err := req.Config.ResolveProfile(req.Profile)
	if err != nil {
		return nil, nil, nil, err
	}

	scope, err := discoveryhttp.NewScopeValidator(endpointScopeSeedURL(req.TargetType, req.TargetValue))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("building scope validator: %w", err)
	}

	seeds, err := s.resolveEndpointSeeds(ctx, target, req, cfg, scope)
	if err != nil {
		return nil, nil, nil, err
	}

	if req.DryRun {
		var sources []string
		if cfg.EnableRobots {
			sources = append(sources, "robots.txt")
		}
		if cfg.EnableSitemap {
			sources = append(sources, "sitemap.xml")
		}
		sources = append(sources, "html")
		if cfg.EnableJavaScript {
			sources = append(sources, "javascript")
		}
		if cfg.EnableOpenAPI {
			sources = append(sources, "openapi/swagger")
		}
		return nil, &EndpointDryRunReport{
			Target: req.TargetValue, Seeds: seeds, MaxDepth: cfg.MaxDepth,
			MaxPages: cfg.MaxPages, MaxEndpoints: cfg.MaxEndpoints, Sources: sources,
		}, nil, nil
	}

	previous, previousParams, err := s.previousEndpoints(ctx, target.ID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading previous endpoint state: %w", err)
	}

	client := discoveryendpoint.NewClientForScope(cfg, scope)
	crawler := discoveryendpoint.NewCrawler(client, scope, s.logger, cfg)

	summary, err := crawler.Scan(ctx, discoveryendpoint.ScanRequest{TargetID: target.ID, SeedURLs: seeds})
	if err != nil {
		return nil, nil, nil, err
	}

	current, currentParams := s.persistEndpointSummary(ctx, target.ID, summary)
	changes := detectEndpointChanges(previous, current, previousParams, currentParams)

	return summary, nil, changes, nil
}

// resolveEndpointSeeds builds the crawl's starting URLs (phase7.md §26):
// req.SeedURLs if explicitly supplied, otherwise every distinct
// scheme+host already known for this target from earlier HTTP/API/AI
// endpoint assets (preferring https when both are known), falling back
// to "https://<value>" for a HOST/DOMAIN target with no prior HTTP
// evidence at all — the same bootstrap Phase 3 uses for its own first
// scan of a target. Every seed is scope-checked before being returned;
// candidates that fail scope are silently dropped, the same defense-in-
// depth every other phase's candidate generation already applies.
func (s *Service) resolveEndpointSeeds(ctx context.Context, target domaintarget.Target, req EndpointRequest, cfg discoveryendpoint.Config, scope *discoveryhttp.ScopeValidator) ([]string, error) {
	var bases []string

	if len(req.SeedURLs) > 0 {
		bases = req.SeedURLs
	} else if req.TargetType == domaintarget.TypeURL {
		bases = []string{req.TargetValue}
	} else {
		known, err := s.knownHTTPBases(ctx, target.ID)
		if err != nil {
			return nil, err
		}
		if len(known) > 0 {
			bases = known
		} else {
			bases = []string{"https://" + req.TargetValue}
		}
	}

	seen := make(map[string]bool)
	var seeds []string
	add := func(raw string) {
		norm, err := domainendpoint.Normalize(raw)
		if err != nil || seen[norm.URL] {
			return
		}
		if !scope.AllowedURL(norm.URL) {
			return
		}
		seen[norm.URL] = true
		seeds = append(seeds, norm.URL)
	}

	for _, base := range bases {
		u, err := url.Parse(base)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		root := u.Scheme + "://" + u.Host
		if len(cfg.SeedPaths) == 0 {
			add(root + "/")
			continue
		}
		for _, p := range cfg.SeedPaths {
			add(root + p)
		}
	}

	return seeds, nil
}

// knownHTTPBases returns every distinct "scheme://host[:port]" already
// known for targetID from previously-discovered HTTP_ENDPOINT/
// API_ENDPOINT/AI_ENDPOINT assets, https preferred over http when both
// exist for the same host (phase7.md §26).
func (s *Service) knownHTTPBases(ctx context.Context, targetID uuid.UUID) ([]string, error) {
	byHost := make(map[string]string) // host -> best known base ("https://..." wins over "http://...")
	cursor := ""
	for {
		page, err := s.assets.List(ctx, assetrepo.ListFilter{
			TargetID: targetID, Pagination: pagination.Params{Limit: pagination.MaxLimit, Cursor: cursor},
		})
		if err != nil {
			return nil, err
		}
		for _, a := range page.Items {
			if a.URL == nil || *a.URL == "" {
				continue
			}
			if a.Type != domainasset.TypeHTTPEndpoint && a.Type != domainasset.TypeAPIEndpoint && a.Type != domainasset.TypeAIEndpoint {
				continue
			}
			u, err := url.Parse(*a.URL)
			if err != nil || u.Scheme == "" || u.Host == "" {
				continue
			}
			base := u.Scheme + "://" + u.Host
			existing, ok := byHost[u.Host]
			if !ok || (u.Scheme == "https" && strings.HasPrefix(existing, "http://")) {
				byHost[u.Host] = base
			}
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	out := make([]string, 0, len(byHost))
	for _, base := range byHost {
		out = append(out, base)
	}
	return out, nil
}

func endpointScopeSeedURL(targetType domaintarget.Type, value string) string {
	if targetType == domaintarget.TypeURL {
		return value
	}
	return "https://" + value
}
