package endpoint

import (
	"context"
	"net/url"
	"time"

	domainendpoint "ai-recon-platform/internal/domain/endpoint"
)

// processRobots fetches /robots.txt for every distinct scheme+host among
// req.SeedURLs, parses it (phase7.md §23), records robots.txt itself as
// a Result, and feeds every discovered path into the depth-0 frontier —
// and, if sitemap discovery is enabled, every discovered Sitemap:
// directive into processSitemaps. A Disallow entry is never treated as
// an authorization boundary — see ParseRobots's doc comment.
func (c *Crawler) processRobots(ctx context.Context, req ScanRequest, acc *accumulator, summary *Summary, visited *visitedSet, limiter *rateLimiter) []Candidate {
	var extraCandidates []Candidate
	var sitemapURLs []string

	for _, host := range distinctHosts(req.SeedURLs) {
		if ctx.Err() != nil {
			return extraCandidates
		}
		robotsURL := host + "/robots.txt"
		cand := Candidate{URL: robotsURL, Method: "GET", Source: "robots", Confidence: 1.0}
		norm, ok := c.normalizeAndCheckScope(cand, summary)
		if !ok || visited.SeenAndMark("GET", norm.URL) {
			continue
		}
		if !awaitLimiter(ctx, limiter) {
			return extraCandidates
		}

		resp, err := c.client.Get(ctx, norm.URL, nil)
		summary.PagesFetched++
		if err != nil {
			continue // robots.txt is optional — its absence is not an error worth reporting
		}
		result := robotsResult(norm, resp.StatusCode, resp.ContentType, len(resp.Body))
		acc.Add(result)
		if resp.StatusCode != 200 {
			continue
		}

		parsed := ParseRobots(resp.Body)
		if c.cfg.EnableSitemap {
			sitemapURLs = append(sitemapURLs, parsed.Sitemaps...)
		}
		for _, p := range parsed.Paths {
			extraCandidates = append(extraCandidates, Candidate{
				URL: p, Base: norm.URL, Method: "GET", Source: "robots", Confidence: 0.5,
				Evidence: "robots.txt: " + p,
			})
		}
	}

	if c.cfg.EnableSitemap {
		for _, host := range distinctHosts(req.SeedURLs) {
			sitemapURLs = append(sitemapURLs, host+"/sitemap.xml")
		}
		extraCandidates = append(extraCandidates, c.processSitemaps(ctx, sitemapURLs, summary, visited, limiter, acc)...)
	}

	return extraCandidates
}

func robotsResult(norm domainendpoint.Normalized, statusCode int, contentType string, contentLength int) Result {
	code := statusCode
	length := int64(contentLength)
	return Result{
		URL: norm.URL, Scheme: norm.Scheme, Host: norm.Host, Port: norm.Port,
		Path: norm.Path, Method: "GET", StatusCode: &code, ContentType: contentType, ContentLength: &length,
		Classification: ClassRobots, Sources: []string{"robots"}, Confidence: 1.0, Observed: true,
		Evidence: map[string]string{"robots": "GET /robots.txt"}, ObservedAt: time.Now().UTC(),
	}
}

// processSitemaps fetches and parses every sitemap URL in seeds (and any
// child sitemaps a sitemap index names), bounded by MaxSitemaps and
// MaxSitemapURLs and protected against cyclic/repeated sitemap references
// via visited (phase7.md §22/§73's "recursive sitemap protection").
func (c *Crawler) processSitemaps(ctx context.Context, seeds []string, summary *Summary, visited *visitedSet, limiter *rateLimiter, acc *accumulator) []Candidate {
	var candidates []Candidate
	queue := append([]string(nil), seeds...)
	sitemapsFetched := 0
	urlsFound := 0
	seenSitemaps := make(map[string]bool)

	for len(queue) > 0 && sitemapsFetched < maxInt(c.cfg.MaxSitemaps, 1) {
		if ctx.Err() != nil {
			break
		}
		next := queue[0]
		queue = queue[1:]

		cand := Candidate{URL: next, Method: "GET", Source: "sitemap"}
		norm, ok := c.normalizeAndCheckScope(cand, summary)
		if !ok || seenSitemaps[norm.URL] || visited.SeenAndMark("GET", norm.URL) {
			continue
		}
		seenSitemaps[norm.URL] = true

		if !awaitLimiter(ctx, limiter) {
			break
		}
		resp, err := c.client.Get(ctx, norm.URL, nil)
		summary.PagesFetched++
		sitemapsFetched++
		if err != nil || resp.StatusCode != 200 {
			continue
		}

		parsed, err := ParseSitemap(resp.Body)
		if err != nil {
			continue
		}
		acc.Add(sitemapDocResult(norm, resp.StatusCode, resp.ContentType, len(resp.Body)))

		for _, childLoc := range parsed.ChildSitemaps {
			if sitemapsFetched+len(queue) < c.cfg.MaxSitemaps {
				queue = append(queue, childLoc)
			}
		}
		for _, u := range parsed.URLs {
			if urlsFound >= maxInt(c.cfg.MaxSitemapURLs, 1) {
				break
			}
			urlsFound++
			candidates = append(candidates, Candidate{
				URL: u, Method: "GET", Source: "sitemap", Confidence: 0.6,
				Evidence: "sitemap.xml <loc>" + u + "</loc>",
			})
		}
	}
	return candidates
}

func sitemapDocResult(norm domainendpoint.Normalized, statusCode int, contentType string, contentLength int) Result {
	code := statusCode
	length := int64(contentLength)
	return Result{
		URL: norm.URL, Scheme: norm.Scheme, Host: norm.Host, Port: norm.Port,
		Path: norm.Path, Method: "GET", StatusCode: &code, ContentType: contentType, ContentLength: &length,
		Classification: ClassSitemap, Sources: []string{"sitemap"}, Confidence: 1.0, Observed: true,
		Evidence: map[string]string{"sitemap": "GET " + norm.Path}, ObservedAt: time.Now().UTC(),
	}
}

// processWellKnownAPIDocs checks the small, fixed list of standard
// OpenAPI/Swagger document locations (phase7.md §19/§20) for every
// distinct scheme+host among req.SeedURLs — never a brute-force path
// guesser, just the well-known, standard set. Every documented operation
// found is added directly to acc as a Documented (not yet Observed)
// endpoint; if the crawl's own independent GET traversal separately
// reaches the same path, the two merge into one Observed+Documented
// Result.
func (c *Crawler) processWellKnownAPIDocs(ctx context.Context, req ScanRequest, acc *accumulator, summary *Summary, visited *visitedSet, limiter *rateLimiter) {
	for _, host := range distinctHosts(req.SeedURLs) {
		for _, docPath := range wellKnownAPIDocPaths {
			if ctx.Err() != nil {
				return
			}
			cand := Candidate{URL: host + docPath, Method: "GET", Source: "openapi"}
			norm, ok := c.normalizeAndCheckScope(cand, summary)
			if !ok || visited.SeenAndMark("GET", norm.URL) {
				continue
			}
			if !awaitLimiter(ctx, limiter) {
				return
			}

			resp, err := c.client.Get(ctx, norm.URL, nil)
			summary.PagesFetched++
			if err != nil || resp.StatusCode != 200 {
				continue
			}

			doc, err := ParseOpenAPI(resp.Body)
			if err != nil || len(doc.Operations) == 0 {
				continue
			}

			class := ClassOpenAPI
			apiType := "openapi"
			if doc.IsSwagger {
				class, apiType = ClassSwagger, "swagger"
			}
			code := resp.StatusCode
			length := int64(len(resp.Body))
			acc.Add(Result{
				URL: norm.URL, Scheme: norm.Scheme, Host: norm.Host, Port: norm.Port,
				Path: norm.Path, Method: "GET", StatusCode: &code, ContentType: resp.ContentType, ContentLength: &length,
				ResponseHash: resp.BodySHA256, Classification: class, APIType: apiType, APIVersion: doc.Version,
				Sources: []string{"openapi"}, Confidence: 0.95, Observed: true, Documented: true,
				Evidence:   map[string]string{"openapi": "GET " + norm.Path},
				ObservedAt: time.Now().UTC(),
			})

			for _, opCand := range candidatesFromOpenAPI(doc, "openapi") {
				opCand.Base = norm.URL
				opNorm, ok := c.normalizeAndCheckScope(opCand, summary)
				if !ok {
					continue
				}
				acc.Add(unfetchedResult(opCand, opNorm))
			}
		}
	}
}

// distinctHosts returns the unique "scheme://host[:port]" prefix of every
// seed URL, in deterministic order.
func distinctHosts(seeds []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range seeds {
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		host := u.Scheme + "://" + u.Host
		if !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
	}
	return out
}
