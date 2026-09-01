package http

import (
	"fmt"
	"net/url"
	"sort"

	domainendpoint "ai-recon-platform/internal/domain/endpoint"
	domaintarget "ai-recon-platform/internal/domain/target"
)

// Candidate is one URL+method combination the scanner will request.
type Candidate struct {
	URL    string // normalized (see internal/domain/endpoint.Normalize) — no query, no fragment
	Method string
}

// GenerateCandidates deterministically builds the full, deduplicated,
// in-scope candidate list for a target.
//
//   - targetType == target.TypeURL: targetValue is used as the single
//     starting URL as-is (phase3.md §8) — cfg.Schemes is not consulted,
//     since the caller already gave an explicit scheme.
//   - targetType == target.TypeHost / target.TypeDomain: a base URL is
//     built for every configured scheme (cfg.Schemes) against
//     targetValue, each using that scheme's default port (no port list is
//     configurable in Phase 3 — see docs/architecture/http-discovery.md).
//
// Every candidate is normalized (endpoint.Normalize — lowercased host,
// cleaned path, default port resolved, no query/fragment), deduplicated
// against that normalized form, and checked against scope before being
// included — a candidate that fails scope validation is silently dropped
// here (it was never going to be requested; this is defense in depth,
// since every candidate is derived directly from the target's own host).
// Output is sorted for determinism regardless of map iteration order.
func GenerateCandidates(targetType domaintarget.Type, targetValue string, cfg Config, paths []string, scope *ScopeValidator) ([]Candidate, error) {
	baseURLs, err := baseURLsFor(targetType, targetValue, cfg)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var candidates []Candidate

	for _, base := range baseURLs {
		baseParsed, err := url.Parse(base)
		if err != nil {
			return nil, fmt.Errorf("parsing base URL %q: %w", base, err)
		}

		for _, p := range paths {
			raw := baseParsed.Scheme + "://" + baseParsed.Host + p
			norm, err := domainendpoint.Normalize(raw)
			if err != nil {
				// A malformed combination of base+path shouldn't fail the
				// whole scan — skip just this candidate.
				continue
			}
			if seen[norm.URL] {
				continue
			}
			if scope != nil && !scope.AllowedURL(norm.URL) {
				continue
			}
			seen[norm.URL] = true

			for _, method := range cfg.Methods {
				candidates = append(candidates, Candidate{URL: norm.URL, Method: method})
			}
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].URL != candidates[j].URL {
			return candidates[i].URL < candidates[j].URL
		}
		return candidates[i].Method < candidates[j].Method
	})

	return candidates, nil
}

func baseURLsFor(targetType domaintarget.Type, targetValue string, cfg Config) ([]string, error) {
	switch targetType {
	case domaintarget.TypeURL:
		return []string{targetValue}, nil
	case domaintarget.TypeHost, domaintarget.TypeDomain:
		if len(cfg.Schemes) == 0 {
			return nil, fmt.Errorf("no schemes configured for HTTP discovery")
		}
		urls := make([]string, 0, len(cfg.Schemes))
		for _, scheme := range cfg.Schemes {
			urls = append(urls, scheme+"://"+targetValue)
		}
		return urls, nil
	default:
		return nil, fmt.Errorf("target type %s is not supported by HTTP discovery (only URL, HOST, DOMAIN)", targetType)
	}
}
