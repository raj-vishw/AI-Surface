package endpoint

import (
	"context"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	discoveryhttp "ai-recon-platform/internal/discovery/http"
	domainendpoint "ai-recon-platform/internal/domain/endpoint"
	"ai-recon-platform/internal/httpclient"
)

// wellKnownAPIDocPaths are the standard OpenAPI/Swagger document
// locations checked when EnableOpenAPI is set (phase7.md §19/§20) —
// never anything beyond this fixed, small, well-known list; this is not
// a brute-force path guesser.
var wellKnownAPIDocPaths = []string{
	"/openapi.json", "/openapi.yaml", "/openapi.yml",
	"/swagger.json", "/swagger.yaml", "/v3/api-docs", "/api-docs",
}

// Crawler executes bounded endpoint discovery against a single authorized
// target, using internal/httpclient (never a second HTTP stack —
// phase7.md §5) and internal/discovery/http.ScopeValidator (never a
// second scope mechanism — phase7.md §54) for every request.
type Crawler struct {
	client *httpclient.Client
	scope  *discoveryhttp.ScopeValidator
	logger *slog.Logger
	cfg    Config
}

// NewCrawler builds a Crawler. client should be built with
// NewClientForScope so its redirect policy is bound to the same scope
// passed here (phase7.md §5/§27: "do not silently follow redirects to
// out-of-scope hosts").
func NewCrawler(client *httpclient.Client, scope *discoveryhttp.ScopeValidator, logger *slog.Logger, cfg Config) *Crawler {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Crawler{client: client, scope: scope, logger: logger, cfg: cfg}
}

// NewClientForScope builds an internal/httpclient.Client whose redirect
// policy is bound to scope — the exact same AllowRedirectTo extension
// point internal/discovery/http.NewClientForScope already established,
// reused directly here rather than reimplemented (phase7.md §5/§27).
func NewClientForScope(cfg Config, scope *discoveryhttp.ScopeValidator) *httpclient.Client {
	maxRedirects := cfg.MaxRedirects
	if !cfg.FollowRedirects {
		maxRedirects = 0
	}
	return httpclient.New(httpclient.Options{
		Timeout:         cfg.Timeout,
		MaxResponseSize: cfg.MaxResponseSize,
		MaxRedirects:    maxRedirects,
		AllowRedirectTo: scope.Allowed,
	})
}

// ScanRequest describes one crawl.
type ScanRequest struct {
	TargetID uuid.UUID
	// SeedURLs are fully-formed starting URLs (phase7.md §26) — the
	// caller (internal/discovery/service) resolves these from the
	// target's own known HTTP(S)/service assets plus
	// Config.SeedPaths, preferring https when both are known.
	SeedURLs []string
}

// Scan runs the bounded crawl described by req, respecting every limit in
// c.cfg and ctx cancellation throughout (phase7.md §84: every crawler
// worker, HTTP request, and the parsing pipeline all stop promptly on
// cancellation; no goroutine is leaked — every phase joins its
// goroutines via sync.WaitGroup before returning, the same discipline
// every other discovery engine in this project follows).
func (c *Crawler) Scan(ctx context.Context, req ScanRequest) (*Summary, error) {
	start := time.Now()
	scanID := uuid.New()
	summary := &Summary{ScanID: scanID, TargetID: req.TargetID}

	acc := newAccumulator(maxInt(c.cfg.MaxEndpoints, 1))
	visited := newVisitedSet()
	limiter := newRateLimiter(c.cfg.RequestsPerSecond)
	if limiter != nil {
		defer limiter.Stop()
	}

	frontier := make([]Candidate, 0, len(req.SeedURLs))
	for _, u := range req.SeedURLs {
		frontier = append(frontier, Candidate{URL: u, Method: "GET", Source: "seed", Confidence: 1.0, Depth: 0})
	}

	// Auxiliary sources (phase7.md §11/§22/§23): independent of the
	// depth-based link crawl, each bounded by the same overall
	// page/endpoint budget. robots.txt/sitemap.xml-derived candidates
	// join the depth-0 frontier (phase7.md §23: a Disallow entry is an
	// ordinary candidate, not a boundary).
	if c.cfg.EnableRobots {
		frontier = append(frontier, c.processRobots(ctx, req, acc, summary, visited, limiter)...)
	}
	if c.cfg.EnableOpenAPI {
		c.processWellKnownAPIDocs(ctx, req, acc, summary, visited, limiter)
	}

	for depth := 0; depth <= c.cfg.MaxDepth && len(frontier) > 0; depth++ {
		if ctx.Err() != nil {
			break
		}
		if summary.PagesFetched >= maxInt(c.cfg.MaxPages, 1) {
			break
		}
		if acc.Full() {
			break
		}
		frontier = c.fetchFrontier(ctx, frontier, acc, summary, visited, limiter)
	}

	summary.Duration = time.Since(start)
	summary.Results = acc.results()
	summary.EndpointsDiscovered = len(summary.Results)
	return summary, nil
}

// fetchFrontier fetches every not-yet-visited, in-scope candidate in
// frontier with bounded concurrency, contributes each outcome to acc, and
// returns the next depth's frontier (links/scripts/JS routes discovered
// along the way) — never exceeding c.cfg.MaxPages/MaxEndpoints
// (phase7.md §24/§52/§53).
func (c *Crawler) fetchFrontier(ctx context.Context, frontier []Candidate, acc *accumulator, summary *Summary, visited *visitedSet, limiter *rateLimiter) []Candidate {
	sem := make(chan struct{}, maxInt(c.cfg.MaxConcurrency, 1))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var nextFrontier []Candidate

	for _, cand := range frontier {
		mu.Lock()
		overBudget := summary.PagesFetched >= maxInt(c.cfg.MaxPages, 1)
		mu.Unlock()
		if overBudget || acc.Full() {
			break
		}

		norm, ok := c.normalizeAndCheckScope(cand, summary)
		if !ok {
			continue
		}
		if visited.SeenAndMark(cand.Method, norm.URL) {
			mu.Lock()
			summary.Duplicates++
			mu.Unlock()
			continue
		}

		wg.Add(1)
		go func(cand Candidate, norm domainendpoint.Normalized) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			if ctx.Err() != nil || !awaitLimiter(ctx, limiter) {
				return
			}

			// Only GET is ever actually requested (phase7.md §30: never
			// send PUT/PATCH/DELETE, and never submit a form, merely to
			// discover whether it works) — a non-GET candidate (a POST
			// form, say) is recorded as a documented/inferred endpoint
			// without ever being fetched, and never counts against the
			// page-fetch budget (no request was made).
			if strings.ToUpper(cand.Method) != "GET" {
				mu.Lock()
				acc.Add(unfetchedResult(cand, norm))
				mu.Unlock()
				return
			}

			mu.Lock()
			summary.PagesFetched++
			pagesFetchedOverBudget := summary.PagesFetched > maxInt(c.cfg.MaxPages, 1)
			mu.Unlock()
			if pagesFetchedOverBudget {
				return
			}

			result, discovered, redirectHops, err := c.fetchAndParse(ctx, cand, norm)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				summary.Errors++
				acc.Add(result) // still record the failed attempt (phase7.md §82/§83)
				return
			}
			acc.Add(result)
			summary.Redirects += redirectHops
			if result.Truncated {
				summary.Truncated++
			}
			if cand.Depth < c.cfg.MaxDepth {
				for _, d := range discovered {
					d.Depth = cand.Depth + 1
					nextFrontier = append(nextFrontier, d)
				}
			}
		}(cand, norm)
	}

	wg.Wait()
	return nextFrontier
}

// normalizeAndCheckScope resolves cand.URL against cand.Base (if any —
// most discovered links/actions are relative, e.g. <a href="/about">,
// and must be resolved against the page they were found on before they
// mean anything), normalizes the result, and validates it against scope —
// the mandatory boundary every candidate passes through before any
// request is even considered (phase7.md §54): never a naive
// strings.Contains check, always the real scope service, applied after
// URL parsing and normalization.
func (c *Crawler) normalizeAndCheckScope(cand Candidate, summary *Summary) (domainendpoint.Normalized, bool) {
	resolved := cand.URL
	if cand.Base != "" {
		baseURL, err := url.Parse(cand.Base)
		if err != nil {
			return domainendpoint.Normalized{}, false
		}
		ref, err := url.Parse(cand.URL)
		if err != nil {
			return domainendpoint.Normalized{}, false
		}
		resolved = baseURL.ResolveReference(ref).String()
	}

	norm, err := domainendpoint.Normalize(resolved)
	if err != nil {
		return domainendpoint.Normalized{}, false
	}
	if !c.scope.AllowedURL(norm.URL) {
		summary.ScopeRejections++
		return domainendpoint.Normalized{}, false
	}
	// norm is the REAL, concrete target — the actual URL fetched. Path
	// templating (phase7.md §38) is applied only when building a Result's
	// *identity* (see applyPathTemplate's call sites in fetch.go), never
	// here: fetching "/users/%7Bid%7D" instead of the real "/users/123"
	// would be a genuine bug, not a normalization.
	return norm, true
}

// applyPathTemplate replaces norm's Path with its templated form (see
// normalizer.go's TemplatePath) when a conservative dynamic segment was
// detected, rebuilding URL to match — this is what makes "/users/123"
// and "/users/456" collapse into one logical endpoint identity,
// "/users/{id}" (phase7.md §38), applied at the single point every
// candidate passes through on its way to being fetched/recorded, never
// duplicated per call site.
func applyPathTemplate(norm domainendpoint.Normalized) domainendpoint.Normalized {
	templated := TemplatePath(norm.Path)
	if templated == norm.Path {
		return norm
	}
	u, err := url.Parse(norm.URL)
	if err != nil {
		return norm
	}
	u.Path = templated
	norm.Path = templated
	norm.URL = u.String()
	return norm
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// rateLimiter paces crawl requests to at most cfg.RequestsPerSecond per
// second — a safety/stability control (phase7.md §56), never
// randomized/stealth timing. nil (RequestsPerSecond <= 0) means
// unlimited.
type rateLimiter struct {
	ticker *time.Ticker
	c      <-chan time.Time
}

func newRateLimiter(requestsPerSecond float64) *rateLimiter {
	if requestsPerSecond <= 0 {
		return nil
	}
	interval := time.Duration(float64(time.Second) / requestsPerSecond)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	t := time.NewTicker(interval)
	return &rateLimiter{ticker: t, c: t.C}
}

func (r *rateLimiter) Stop() { r.ticker.Stop() }

func awaitLimiter(ctx context.Context, limiter *rateLimiter) bool {
	if limiter == nil {
		return true
	}
	select {
	case <-limiter.c:
		return true
	case <-ctx.Done():
		return false
	}
}

// visitedSet tracks every (method, normalized URL) pair already
// dispatched, so cyclic links (phase7.md §53: "/a -> /b, /b -> /a") and
// ordinary duplicate links never cause a second fetch.
type visitedSet struct {
	mu   sync.Mutex
	seen map[string]bool
}

func newVisitedSet() *visitedSet { return &visitedSet{seen: make(map[string]bool)} }

// SeenAndMark reports whether (method, url) was already visited and, if
// not, marks it visited — an atomic check-and-set so concurrent workers
// racing on the same URL never both proceed.
func (v *visitedSet) SeenAndMark(method, url string) bool {
	key := method + " " + url
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen[key] {
		return true
	}
	v.seen[key] = true
	return false
}

// splitQuery separates path from query for building Parameter entries
// from a candidate's raw URL query string.
// parametersFromQueryPattern converts a Normalized.QueryPattern (already
// the sorted, deduplicated, comma-joined set of query parameter *names*
// produced by internal/domain/endpoint.Normalize — see its doc comment
// on why values are discarded there, not here) into Parameter entries.
// Never re-parses the URL itself: Normalize has already stripped the
// query string out of norm.URL by the time a caller reaches this point,
// so QueryPattern is the only remaining source of parameter names.
func parametersFromQueryPattern(queryPattern string) []Parameter {
	if queryPattern == "" {
		return nil
	}
	names := strings.Split(queryPattern, ",")
	out := make([]Parameter, len(names))
	for i, n := range names {
		out[i] = Parameter{Name: n, Location: "query"}
	}
	return out
}
