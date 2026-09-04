package endpoint

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	discoveryhttp "ai-recon-platform/internal/discovery/http"
	endpointfixture "ai-recon-platform/test/fixtures/endpoint"
)

func testCrawlerConfig() Config {
	return Config{
		Timeout: 2 * time.Second, MaxConcurrency: 5, MaxResponseSize: 1024 * 1024,
		MaxDepth: 3, MaxPages: 100, MaxEndpoints: 1000,
		FollowRedirects: true, MaxRedirects: 5,
		EnableRobots: true, EnableSitemap: true, EnableJavaScript: true, EnableOpenAPI: true,
		MaxSitemaps: 5, MaxSitemapURLs: 100,
	}
}

func newTestCrawler(t *testing.T, fixtureURL string, cfg Config) *Crawler {
	t.Helper()
	scope, err := discoveryhttp.NewScopeValidator(fixtureURL)
	if err != nil {
		t.Fatalf("NewScopeValidator: %v", err)
	}
	client := NewClientForScope(cfg, scope)
	return NewCrawler(client, scope, nil, cfg)
}

func findEndpoint(results []Result, method, path string) (Result, bool) {
	for _, r := range results {
		if r.Method == method && r.Path == path {
			return r, true
		}
	}
	return Result{}, false
}

func TestCrawler_DiscoversHTMLLinks(t *testing.T) {
	fixture := endpointfixture.New()
	defer fixture.Close()
	c := newTestCrawler(t, fixture.URL(), testCrawlerConfig())

	summary, err := c.Scan(context.Background(), ScanRequest{TargetID: uuid.New(), SeedURLs: []string{fixture.URL() + "/"}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	for _, path := range []string{"/", "/about", "/login"} {
		if _, ok := findEndpoint(summary.Results, "GET", path); !ok {
			t.Errorf("expected GET %s among results", path)
		}
	}
}

func TestCrawler_DuplicateLinksNotDoubleFetched(t *testing.T) {
	fixture := endpointfixture.New()
	defer fixture.Close()
	c := newTestCrawler(t, fixture.URL(), testCrawlerConfig())

	summary, err := c.Scan(context.Background(), ScanRequest{TargetID: uuid.New(), SeedURLs: []string{fixture.URL() + "/"}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	count := 0
	for _, r := range summary.Results {
		if r.Method == "GET" && r.Path == "/about" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("/about appeared %d times in Results, want exactly 1 (duplicate <a href> collapsed)", count)
	}
	if summary.Duplicates == 0 {
		t.Error("expected summary.Duplicates > 0 for the duplicate /about link")
	}
}

func TestCrawler_CyclicLinksTerminate(t *testing.T) {
	fixture := endpointfixture.New()
	defer fixture.Close()
	cfg := testCrawlerConfig()
	c := newTestCrawler(t, fixture.URL(), cfg)

	done := make(chan struct{})
	var summary *Summary
	var err error
	go func() {
		summary, err = c.Scan(context.Background(), ScanRequest{TargetID: uuid.New(), SeedURLs: []string{fixture.URL() + "/a"}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Scan did not terminate against a cyclic /a <-> /b link graph — likely an infinite crawl loop")
	}
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	aResult, aOK := findEndpoint(summary.Results, "GET", "/a")
	bResult, bOK := findEndpoint(summary.Results, "GET", "/b")
	if !aOK || !bOK {
		t.Fatalf("expected both /a and /b discovered, got %+v / %+v", aResult, bResult)
	}
}

func TestCrawler_FormDiscoveredNeverSubmitted(t *testing.T) {
	fixture := endpointfixture.New()
	defer fixture.Close()
	c := newTestCrawler(t, fixture.URL(), testCrawlerConfig())

	summary, err := c.Scan(context.Background(), ScanRequest{TargetID: uuid.New(), SeedURLs: []string{fixture.URL() + "/login"}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	loginPost, ok := findEndpoint(summary.Results, "POST", "/login")
	if !ok {
		t.Fatalf("expected the login form's POST /login to be discovered, got %+v", summary.Results)
	}
	if loginPost.Observed {
		t.Error("POST /login must never be Observed=true — the crawler must never actually submit a form (phase7.md §13/§30)")
	}
	if loginPost.StatusCode != nil {
		t.Errorf("POST /login StatusCode = %v, want nil (never actually requested)", loginPost.StatusCode)
	}

	var fieldNames []string
	for _, p := range loginPost.Parameters {
		fieldNames = append(fieldNames, p.Name)
	}
	hasUsername, hasPassword := false, false
	for _, n := range fieldNames {
		if n == "username" {
			hasUsername = true
		}
		if n == "password" {
			hasPassword = true
		}
	}
	if !hasUsername || !hasPassword {
		t.Errorf("expected username/password field names recorded, got %v", fieldNames)
	}
}

func TestCrawler_JavaScriptExtraction(t *testing.T) {
	fixture := endpointfixture.New()
	defer fixture.Close()
	c := newTestCrawler(t, fixture.URL(), testCrawlerConfig())

	summary, err := c.Scan(context.Background(), ScanRequest{TargetID: uuid.New(), SeedURLs: []string{fixture.URL() + "/"}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	strong, ok := findEndpoint(summary.Results, "GET", "/api/v1/users")
	if !ok {
		t.Fatalf("expected /api/v1/users discovered via JavaScript fetch(), got %v", summary.Results)
	}
	foundJS := false
	for _, s := range strong.Sources {
		if s == "javascript" {
			foundJS = true
		}
	}
	if !foundJS {
		t.Errorf("expected 'javascript' among Sources for /api/v1/users, got %v", strong.Sources)
	}
}

func TestCrawler_OpenAPIDiscovery(t *testing.T) {
	fixture := endpointfixture.New()
	defer fixture.Close()
	c := newTestCrawler(t, fixture.URL(), testCrawlerConfig())

	summary, err := c.Scan(context.Background(), ScanRequest{TargetID: uuid.New(), SeedURLs: []string{fixture.URL() + "/"}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	openapiDoc, ok := findEndpoint(summary.Results, "GET", "/openapi.json")
	if !ok {
		t.Fatalf("expected the OpenAPI document itself discovered, got %v", summary.Results)
	}
	if openapiDoc.Classification != ClassOpenAPI {
		t.Errorf("Classification = %s, want openapi", openapiDoc.Classification)
	}

	// GET /api/users is documented AND (via HTML link + JS) actually
	// observed — must be both.
	getUsers, ok := findEndpoint(summary.Results, "GET", "/api/users")
	if !ok {
		t.Fatalf("expected GET /api/users discovered, got %v", summary.Results)
	}
	if !getUsers.Documented {
		t.Error("GET /api/users: Documented = false, want true (named in openapi.json)")
	}
	if !getUsers.Observed {
		t.Error("GET /api/users: Observed = false, want true (an actual HTTP response was received)")
	}

	// DELETE /api/users/{id} is documented but never actually requested —
	// documented-only, never observed (phase7.md §46/§47).
	deleteUser, ok := findEndpoint(summary.Results, "DELETE", "/api/users/{id}")
	if !ok {
		t.Fatalf("expected DELETE /api/users/{id} recorded as documented, got %v", summary.Results)
	}
	if !deleteUser.Documented {
		t.Error("DELETE /api/users/{id}: Documented = false, want true")
	}
	if deleteUser.Observed {
		t.Error("DELETE /api/users/{id}: Observed = true — the crawler must never actually send DELETE (phase7.md §30/§31)")
	}
}

func TestCrawler_RobotsAndSitemap(t *testing.T) {
	fixture := endpointfixture.New()
	defer fixture.Close()
	c := newTestCrawler(t, fixture.URL(), testCrawlerConfig())

	summary, err := c.Scan(context.Background(), ScanRequest{TargetID: uuid.New(), SeedURLs: []string{fixture.URL() + "/"}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	robots, ok := findEndpoint(summary.Results, "GET", "/robots.txt")
	if !ok || robots.Classification != ClassRobots {
		t.Fatalf("expected /robots.txt classified as robots, got %+v", robots)
	}
	sitemap, ok := findEndpoint(summary.Results, "GET", "/sitemap.xml")
	if !ok || sitemap.Classification != ClassSitemap {
		t.Fatalf("expected /sitemap.xml classified as sitemap, got %+v", sitemap)
	}

	// robots.txt's Disallow: /admin must still appear as an ordinary
	// candidate, never suppressed (phase7.md §23/§74) — even though
	// /admin 404s on this fixture (no handler registered), it must still
	// have been *attempted*.
	admin, ok := findEndpoint(summary.Results, "GET", "/admin")
	if !ok {
		t.Fatalf("expected /admin (a Disallow entry) to still be an attempted candidate, got %v", summary.Results)
	}
	if !admin.Observed {
		t.Error("expected /admin to have actually been requested (robots.txt is not an authorization boundary)")
	}
}

func TestCrawler_RedirectFollowedInScope(t *testing.T) {
	fixture := endpointfixture.New()
	defer fixture.Close()
	c := newTestCrawler(t, fixture.URL(), testCrawlerConfig())

	summary, err := c.Scan(context.Background(), ScanRequest{TargetID: uuid.New(), SeedURLs: []string{fixture.URL() + "/redirect"}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if summary.Redirects == 0 {
		t.Error("expected at least one redirect recorded")
	}
}

func TestCrawler_ExternalLinkNotCrawled(t *testing.T) {
	fixture := endpointfixture.New()
	defer fixture.Close()
	c := newTestCrawler(t, fixture.URL(), testCrawlerConfig())

	summary, err := c.Scan(context.Background(), ScanRequest{TargetID: uuid.New(), SeedURLs: []string{fixture.URL() + "/external-link"}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, r := range summary.Results {
		if r.Host == "cdn.example.net" {
			t.Errorf("external host was crawled: %+v", r)
		}
	}
	if summary.ScopeRejections == 0 {
		t.Error("expected the external link to be recorded as a scope rejection")
	}
}

func TestCrawler_DynamicPathTemplating(t *testing.T) {
	fixture := endpointfixture.New()
	defer fixture.Close()
	c := newTestCrawler(t, fixture.URL(), testCrawlerConfig())

	summary, err := c.Scan(context.Background(), ScanRequest{TargetID: uuid.New(), SeedURLs: []string{
		fixture.URL() + "/users/123", fixture.URL() + "/users/456", fixture.URL() + "/users/admin",
	}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	templated, ok := findEndpoint(summary.Results, "GET", "/users/{id}")
	if !ok {
		t.Fatalf("expected /users/123 and /users/456 to template to /users/{id}, got %v", summary.Results)
	}
	if templated.Confidence <= 0 {
		t.Error("expected a positive confidence for the templated endpoint")
	}
	if _, ok := findEndpoint(summary.Results, "GET", "/users/admin"); !ok {
		t.Error("expected /users/admin to remain untemplated and separately discovered")
	}
	if _, ok := findEndpoint(summary.Results, "GET", "/users/123"); ok {
		t.Error("expected /users/123 to NOT appear literally — it should have templated into /users/{id}")
	}
}

func TestCrawler_QueryParametersRecorded(t *testing.T) {
	fixture := endpointfixture.New()
	defer fixture.Close()
	c := newTestCrawler(t, fixture.URL(), testCrawlerConfig())

	summary, err := c.Scan(context.Background(), ScanRequest{TargetID: uuid.New(), SeedURLs: []string{
		fixture.URL() + "/api/users?page=1",
	}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	result, ok := findEndpoint(summary.Results, "GET", "/api/users")
	if !ok {
		t.Fatalf("expected GET /api/users, got %v", summary.Results)
	}
	found := false
	for _, p := range result.Parameters {
		if p.Name == "page" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected parameter 'page' recorded, got %+v", result.Parameters)
	}
	if result.QueryPattern != "page" {
		t.Errorf("QueryPattern = %q, want %q", result.QueryPattern, "page")
	}
}

func TestCrawler_DepthLimit(t *testing.T) {
	fixture := endpointfixture.New()
	defer fixture.Close()
	cfg := testCrawlerConfig()
	cfg.MaxDepth = 0
	cfg.EnableRobots, cfg.EnableSitemap, cfg.EnableOpenAPI, cfg.EnableJavaScript = false, false, false, false
	c := newTestCrawler(t, fixture.URL(), cfg)

	summary, err := c.Scan(context.Background(), ScanRequest{TargetID: uuid.New(), SeedURLs: []string{fixture.URL() + "/"}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if _, ok := findEndpoint(summary.Results, "GET", "/about"); ok {
		t.Error("expected /about NOT to be discovered at MaxDepth=0 (it is only reachable one hop from the seed)")
	}
	if _, ok := findEndpoint(summary.Results, "GET", "/"); !ok {
		t.Error("expected the seed itself to still be fetched at depth 0")
	}
}

func TestCrawler_PageLimit(t *testing.T) {
	fixture := endpointfixture.New()
	defer fixture.Close()
	cfg := testCrawlerConfig()
	cfg.MaxPages = 1
	cfg.EnableRobots, cfg.EnableSitemap, cfg.EnableOpenAPI = false, false, false
	c := newTestCrawler(t, fixture.URL(), cfg)

	summary, err := c.Scan(context.Background(), ScanRequest{TargetID: uuid.New(), SeedURLs: []string{fixture.URL() + "/"}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if summary.PagesFetched > 1 {
		t.Errorf("PagesFetched = %d, want at most 1 (MaxPages=1)", summary.PagesFetched)
	}
}

func TestCrawler_EndpointLimit(t *testing.T) {
	fixture := endpointfixture.New()
	defer fixture.Close()
	cfg := testCrawlerConfig()
	cfg.MaxEndpoints = 2
	c := newTestCrawler(t, fixture.URL(), cfg)

	summary, err := c.Scan(context.Background(), ScanRequest{TargetID: uuid.New(), SeedURLs: []string{fixture.URL() + "/"}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if summary.EndpointsDiscovered > 2 {
		t.Errorf("EndpointsDiscovered = %d, want at most 2 (MaxEndpoints=2)", summary.EndpointsDiscovered)
	}
}

func TestCrawler_ScopeRejection(t *testing.T) {
	fixture := endpointfixture.New()
	defer fixture.Close()
	c := newTestCrawler(t, fixture.URL(), testCrawlerConfig())

	summary, err := c.Scan(context.Background(), ScanRequest{TargetID: uuid.New(), SeedURLs: []string{"https://evil-example.test/"}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if summary.PagesFetched != 0 {
		t.Errorf("PagesFetched = %d, want 0 — an out-of-scope seed must never be requested", summary.PagesFetched)
	}
}

func TestCrawler_ContextCancellation(t *testing.T) {
	fixture := endpointfixture.New()
	defer fixture.Close()
	c := newTestCrawler(t, fixture.URL(), testCrawlerConfig())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	summary, err := c.Scan(ctx, ScanRequest{TargetID: uuid.New(), SeedURLs: []string{fixture.URL() + "/"}})
	if err != nil {
		t.Fatalf("Scan with a cancelled context should return a summary, not an error: %v", err)
	}
	if summary.PagesFetched != 0 {
		t.Errorf("PagesFetched = %d, want 0 under an already-cancelled context", summary.PagesFetched)
	}
}

func TestCrawler_ResponseSizeLimit(t *testing.T) {
	fixture := endpointfixture.New()
	defer fixture.Close()
	cfg := testCrawlerConfig()
	cfg.MaxResponseSize = 1 // absurdly small — every response will exceed it
	cfg.EnableRobots, cfg.EnableSitemap, cfg.EnableOpenAPI, cfg.EnableJavaScript = false, false, false, false
	c := newTestCrawler(t, fixture.URL(), cfg)

	summary, err := c.Scan(context.Background(), ScanRequest{TargetID: uuid.New(), SeedURLs: []string{fixture.URL() + "/"}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	root, ok := findEndpoint(summary.Results, "GET", "/")
	if !ok {
		t.Fatalf("expected the seed still recorded even though it was truncated, got %v", summary.Results)
	}
	if !root.Truncated {
		t.Error("expected Truncated = true for a response exceeding MaxResponseSize")
	}
}
