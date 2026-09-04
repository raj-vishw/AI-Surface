//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	discoveryendpoint "ai-recon-platform/internal/discovery/endpoint"
	discoverysvc "ai-recon-platform/internal/discovery/service"
	domainasset "ai-recon-platform/internal/domain/asset"
	domaintarget "ai-recon-platform/internal/domain/target"
	assetrepo "ai-recon-platform/internal/repository/asset"
	endpointrepo "ai-recon-platform/internal/repository/endpoint"
	assetsvc "ai-recon-platform/internal/service/asset"
	targetsvc "ai-recon-platform/internal/service/target"
	endpointfixture "ai-recon-platform/test/fixtures/endpoint"
)

// endpointTestConfig returns a small, fast endpoint discovery
// configuration suitable for integration tests against the local
// fixture.
func endpointTestConfig() discoveryendpoint.Config {
	return discoveryendpoint.Config{
		Timeout: 5 * time.Second, MaxConcurrency: 5, MaxResponseSize: 1024 * 1024,
		MaxDepth: 3, MaxPages: 100, MaxEndpoints: 1000,
		FollowRedirects: true, MaxRedirects: 5,
		EnableRobots: true, EnableSitemap: true, EnableJavaScript: true, EnableOpenAPI: true,
		MaxSitemaps: 5, MaxSitemapURLs: 100,
	}
}

func createAuthorizedEndpointFixtureTarget(t *testing.T, targets *targetsvc.Service, fixture *endpointfixture.Server) domaintarget.Target {
	t.Helper()
	ctx := context.Background()

	target, err := targets.Create(ctx, targetsvc.CreateInput{
		Name: "endpoint discovery fixture " + uniqueValue("endpoint"), Type: domaintarget.TypeURL, Value: fixture.URL(),
	})
	if err != nil {
		t.Fatalf("creating target: %v", err)
	}
	authorized, err := targets.UpdateAuthorizationStatus(ctx, target.ID, domaintarget.AuthorizationAuthorized)
	if err != nil {
		t.Fatalf("authorizing target: %v", err)
	}
	return authorized
}

func TestEndpointPersistence_EndToEnd(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	fixture := endpointfixture.New()
	defer fixture.Close()
	target := createAuthorizedEndpointFixtureTarget(t, targets, fixture)

	summary, dryRun, changes, err := discovery.RunEndpoint(context.Background(), discoverysvc.EndpointRequest{
		TargetType: domaintarget.TypeURL, TargetValue: fixture.URL(), Config: endpointTestConfig(),
	})
	if err != nil {
		t.Fatalf("RunEndpoint() failed: %v", err)
	}
	if dryRun != nil {
		t.Fatal("expected a real scan, not a dry-run report")
	}
	if summary.EndpointsDiscovered == 0 {
		t.Fatal("expected at least one endpoint discovered")
	}
	// First-ever scan: every discovered endpoint is "added".
	if len(changes) != summary.EndpointsDiscovered {
		t.Errorf("changes = %d, want %d (every endpoint should be 'added' on a first scan)", len(changes), summary.EndpointsDiscovered)
	}

	page, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	var apiUsersAsset *domainasset.Asset
	for i, a := range page.Items {
		if a.URL != nil && *a.URL == fixture.URL()+"/api/users" {
			apiUsersAsset = &page.Items[i]
		}
	}
	if apiUsersAsset == nil {
		t.Fatalf("expected an asset for %s/api/users, got %d assets", fixture.URL(), len(page.Items))
	}
	if apiUsersAsset.Type != domainasset.TypeAPIEndpoint {
		t.Errorf("asset.Type = %s, want %s", apiUsersAsset.Type, domainasset.TypeAPIEndpoint)
	}
	if apiUsersAsset.Source != "endpoint" {
		t.Errorf("asset.Source = %q, want %q", apiUsersAsset.Source, "endpoint")
	}

	endpointsPage, err := assets.ListEndpoints(context.Background(), endpointrepo.ListFilter{AssetID: apiUsersAsset.ID})
	if err != nil {
		t.Fatalf("ListEndpoints() failed: %v", err)
	}
	if len(endpointsPage.Items) != 1 {
		t.Fatalf("expected exactly 1 endpoint row for %s/api/users, got %d", fixture.URL(), len(endpointsPage.Items))
	}
	getUsers := endpointsPage.Items[0]
	if !getUsers.Documented {
		t.Error("GET /api/users: Documented = false, want true (named in openapi.json)")
	}
	if !getUsers.Observed {
		t.Error("GET /api/users: Observed = false, want true (actually fetched via HTML link/JS)")
	}
	if getUsers.StatusCode == nil || *getUsers.StatusCode != 200 {
		t.Errorf("StatusCode = %v, want 200", getUsers.StatusCode)
	}

	// Parameters: /api/users?page=1 (from the seed's own query, if
	// crawled with one) is not part of this default scan, but the
	// endpoint's classification/api metadata should still be present.
	if getUsers.APIType == "" {
		t.Error("expected a non-empty APIType for an API-classified endpoint")
	}
}

func TestEndpointPersistence_ParametersPersistedNamesOnly(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	fixture := endpointfixture.New()
	defer fixture.Close()
	target := createAuthorizedEndpointFixtureTarget(t, targets, fixture)

	_, _, _, err := discovery.RunEndpoint(context.Background(), discoverysvc.EndpointRequest{
		TargetType: domaintarget.TypeURL, TargetValue: fixture.URL() + "/api/users?page=1",
		Config: endpointTestConfig(),
	})
	if err != nil {
		t.Fatalf("RunEndpoint() failed: %v", err)
	}

	page, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	var apiUsersAsset *domainasset.Asset
	for i, a := range page.Items {
		if a.URL != nil && *a.URL == fixture.URL()+"/api/users" {
			apiUsersAsset = &page.Items[i]
		}
	}
	if apiUsersAsset == nil {
		t.Fatalf("expected an asset for %s/api/users", fixture.URL())
	}
	endpointsPage, err := assets.ListEndpoints(context.Background(), endpointrepo.ListFilter{AssetID: apiUsersAsset.ID})
	if err != nil || len(endpointsPage.Items) != 1 {
		t.Fatalf("ListEndpoints(): %v, items=%d", err, len(endpointsPage.Items))
	}

	params, err := assets.ListEndpointParameters(context.Background(), endpointsPage.Items[0].ID)
	if err != nil {
		t.Fatalf("ListEndpointParameters() failed: %v", err)
	}
	found := false
	for _, p := range params {
		if p.Name == "page" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a 'page' parameter recorded, got %+v", params)
	}
}

func TestEndpointPersistence_IdempotentReanalysis(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	fixture := endpointfixture.New()
	defer fixture.Close()
	target := createAuthorizedEndpointFixtureTarget(t, targets, fixture)
	req := discoverysvc.EndpointRequest{TargetType: domaintarget.TypeURL, TargetValue: fixture.URL() + "/about", Config: endpointTestConfig()}

	if _, _, _, err := discovery.RunEndpoint(context.Background(), req); err != nil {
		t.Fatalf("first RunEndpoint() failed: %v", err)
	}
	firstPage, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	firstCount := len(firstPage.Items)

	time.Sleep(10 * time.Millisecond)

	if _, _, _, err := discovery.RunEndpoint(context.Background(), req); err != nil {
		t.Fatalf("second RunEndpoint() failed: %v", err)
	}
	secondPage, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(secondPage.Items) != firstCount {
		t.Errorf("re-scanning created new assets: first=%d second=%d", firstCount, len(secondPage.Items))
	}

	var about *domainasset.Asset
	for i, a := range secondPage.Items {
		if a.URL != nil && *a.URL == fixture.URL()+"/about" {
			about = &secondPage.Items[i]
		}
	}
	if about == nil {
		t.Fatal("expected an asset for /about")
	}
	if !about.LastSeen.After(about.FirstSeen) {
		t.Errorf("LastSeen (%v) did not advance past FirstSeen (%v) across re-scan", about.LastSeen, about.FirstSeen)
	}
}

func TestEndpointPersistence_ChangeDetection_Added(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	fixture := endpointfixture.New()
	defer fixture.Close()
	createAuthorizedEndpointFixtureTarget(t, targets, fixture)

	cfg := endpointTestConfig()
	cfg.MaxDepth = 0 // just the seed itself, no crawling
	cfg.EnableRobots, cfg.EnableSitemap, cfg.EnableOpenAPI = false, false, false

	// First scan: only /about.
	first, _, firstChanges, err := discovery.RunEndpoint(context.Background(), discoverysvc.EndpointRequest{
		TargetType: domaintarget.TypeURL, TargetValue: fixture.URL() + "/about", Config: cfg,
	})
	if err != nil {
		t.Fatalf("first RunEndpoint() failed: %v", err)
	}
	if first.EndpointsDiscovered == 0 {
		t.Fatal("expected at least 1 endpoint from the first scan")
	}
	for _, c := range firstChanges {
		if c.Type != discoverysvc.EndpointChangeAdded {
			t.Errorf("expected only 'added' changes on the first scan, got %s", c.Type)
		}
	}

	// Second scan: a different page (/login) — new endpoint relative to
	// the target's accumulated history.
	_, _, secondChanges, err := discovery.RunEndpoint(context.Background(), discoverysvc.EndpointRequest{
		TargetType: domaintarget.TypeURL, TargetValue: fixture.URL() + "/login", Config: cfg,
	})
	if err != nil {
		t.Fatalf("second RunEndpoint() failed: %v", err)
	}
	foundAdded := false
	for _, c := range secondChanges {
		if c.Type == discoverysvc.EndpointChangeAdded && c.URL == fixture.URL()+"/login" {
			foundAdded = true
		}
	}
	if !foundAdded {
		t.Errorf("expected an 'added' change for /login, got %+v", secondChanges)
	}
}

func TestEndpointPersistence_UnauthorizedTargetRefused(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	fixture := endpointfixture.New()
	defer fixture.Close()

	target, err := targets.Create(context.Background(), targetsvc.CreateInput{
		Name: "unauthorized endpoint target", Type: domaintarget.TypeURL, Value: fixture.URL(),
	})
	if err != nil {
		t.Fatalf("creating target: %v", err)
	}

	_, _, _, err = discovery.RunEndpoint(context.Background(), discoverysvc.EndpointRequest{
		TargetType: domaintarget.TypeURL, TargetValue: fixture.URL(), Config: endpointTestConfig(),
	})
	if err == nil {
		t.Fatal("expected RunEndpoint() to refuse an unauthorized target")
	}

	page, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("expected no assets persisted for a refused (unauthorized) scan, got %d", len(page.Items))
	}
}

func TestEndpointPersistence_DryRunPersistsNothing(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	fixture := endpointfixture.New()
	defer fixture.Close()
	target := createAuthorizedEndpointFixtureTarget(t, targets, fixture)

	summary, dryRun, changes, err := discovery.RunEndpoint(context.Background(), discoverysvc.EndpointRequest{
		TargetType: domaintarget.TypeURL, TargetValue: fixture.URL(), DryRun: true, Config: endpointTestConfig(),
	})
	if err != nil {
		t.Fatalf("RunEndpoint() failed: %v", err)
	}
	if summary != nil {
		t.Fatal("expected a dry-run report, not a Summary")
	}
	if dryRun == nil || len(dryRun.Seeds) == 0 {
		t.Fatalf("expected a dry-run report naming at least one seed, got %+v", dryRun)
	}
	if changes != nil {
		t.Errorf("expected no Changes in dry-run mode, got %+v", changes)
	}

	page, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("expected no assets persisted in dry-run mode, got %d", len(page.Items))
	}
}
