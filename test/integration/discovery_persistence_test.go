//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	discoveryhttp "ai-recon-platform/internal/discovery/http"
	discoverysvc "ai-recon-platform/internal/discovery/service"
	domainasset "ai-recon-platform/internal/domain/asset"
	domaintarget "ai-recon-platform/internal/domain/target"
	assetrepo "ai-recon-platform/internal/repository/asset"
	endpointrepo "ai-recon-platform/internal/repository/endpoint"
	assetsvc "ai-recon-platform/internal/service/asset"
	targetsvc "ai-recon-platform/internal/service/target"
	httpfixture "ai-recon-platform/test/fixtures/http"
)

// discoveryTestConfig returns a small, fast discovery configuration
// suitable for integration tests against the local fixture server.
func discoveryTestConfig(paths []string) discoveryhttp.Config {
	return discoveryhttp.Config{
		Timeout:           5 * time.Second,
		MaxConcurrency:    5,
		MaxResponseSize:   1024 * 1024, // 1 MiB — deliberately smaller than the fixture's /large-response
		FollowRedirects:   true,
		MaxRedirects:      5,
		Methods:           []string{"GET"},
		Schemes:           []string{"http"},
		DetectAIEndpoints: true,
		Paths:             paths,
	}
}

// createAuthorizedFixtureTarget creates and authorizes a Target pointing
// at fixture's URL, returning it.
func createAuthorizedFixtureTarget(t *testing.T, targets *targetsvc.Service, fixture *httpfixture.Server) domaintarget.Target {
	t.Helper()
	ctx := context.Background()

	target, err := targets.Create(ctx, targetsvc.CreateInput{
		Name: "discovery fixture", Type: domaintarget.TypeURL, Value: fixture.URL(),
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

func TestDiscoveryPersistence_EndToEnd(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	fixture := httpfixture.New()
	defer fixture.Close()

	target := createAuthorizedFixtureTarget(t, targets, fixture)

	paths := []string{"/", "/openapi.json", "/v1/models", "/health"}
	summary, dryRun, err := discovery.Run(context.Background(), discoverysvc.Request{
		TargetType: domaintarget.TypeURL, TargetValue: fixture.URL(), Config: discoveryTestConfig(paths),
	})
	if err != nil {
		t.Fatalf("Run() failed: %v", err)
	}
	if dryRun != nil {
		t.Fatal("expected a real scan, not a dry-run report")
	}
	if summary.Successful != len(paths) {
		t.Fatalf("expected all %d paths to succeed, got %d successful (results: %+v)", len(paths), summary.Successful, summary.Results)
	}
	if summary.AICandidates != 1 {
		t.Errorf("expected exactly 1 AI candidate (/v1/models), got %d", summary.AICandidates)
	}

	page, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(page.Items) != len(paths) {
		t.Fatalf("expected %d distinct assets (one per path, all different URLs), got %d", len(paths), len(page.Items))
	}

	var foundAICandidate bool
	for _, a := range page.Items {
		if a.Type == domainasset.TypeAIEndpoint {
			foundAICandidate = true
			if a.Source != "http" {
				t.Errorf("asset.Source = %q, want %q", a.Source, "http")
			}
		}
		evidence, err := assets.ListEvidence(context.Background(), assetrepo.EvidenceListFilter{AssetID: a.ID})
		if err != nil {
			t.Fatalf("ListEvidence() failed: %v", err)
		}
		if len(evidence.Items) == 0 {
			t.Errorf("asset %s has no evidence recorded", a.ID)
		} else if evidence.Items[0].EvidenceType != domainasset.EvidenceHTTPResponse {
			t.Errorf("evidence type = %s, want %s", evidence.Items[0].EvidenceType, domainasset.EvidenceHTTPResponse)
		}

		endpoints, err := assets.ListEndpoints(context.Background(), endpointFilter(a.ID))
		if err != nil {
			t.Fatalf("ListEndpoints() failed: %v", err)
		}
		if len(endpoints.Items) != 1 {
			t.Errorf("asset %s: expected exactly 1 endpoint, got %d", a.ID, len(endpoints.Items))
		}
	}
	if !foundAICandidate {
		t.Error("expected at least one asset classified as AI_ENDPOINT (/v1/models)")
	}
}

func TestDiscoveryPersistence_RescanPreservesFirstSeenAdvancesLastSeen(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	fixture := httpfixture.New()
	defer fixture.Close()

	target := createAuthorizedFixtureTarget(t, targets, fixture)
	paths := []string{"/health"}
	req := discoverysvc.Request{TargetType: domaintarget.TypeURL, TargetValue: fixture.URL(), Config: discoveryTestConfig(paths)}

	if _, _, err := discovery.Run(context.Background(), req); err != nil {
		t.Fatalf("first Run() failed: %v", err)
	}
	firstPage, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(firstPage.Items) != 1 {
		t.Fatalf("expected exactly 1 asset after first scan, got %d", len(firstPage.Items))
	}
	first := firstPage.Items[0]

	time.Sleep(10 * time.Millisecond) // ensure a measurably later LastSeen

	if _, _, err := discovery.Run(context.Background(), req); err != nil {
		t.Fatalf("second Run() failed: %v", err)
	}
	secondPage, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(secondPage.Items) != 1 {
		t.Fatalf("expected the second scan to deduplicate to the same 1 asset, got %d", len(secondPage.Items))
	}
	second := secondPage.Items[0]

	if second.ID != first.ID {
		t.Fatalf("re-scanning the same target created a new asset row: %v vs %v", first.ID, second.ID)
	}
	if !second.FirstSeen.Equal(first.FirstSeen) {
		t.Errorf("FirstSeen changed across re-scan: %v -> %v", first.FirstSeen, second.FirstSeen)
	}
	if !second.LastSeen.After(first.LastSeen) {
		t.Errorf("LastSeen did not advance across re-scan: %v -> %v", first.LastSeen, second.LastSeen)
	}
}

func TestDiscoveryPersistence_ResponseChangeUpdatesHashPreservesIdentity(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	fixture := httpfixture.New()
	defer fixture.Close()

	target := createAuthorizedFixtureTarget(t, targets, fixture)
	paths := []string{"/v1/models"}
	req := discoverysvc.Request{TargetType: domaintarget.TypeURL, TargetValue: fixture.URL(), Config: discoveryTestConfig(paths)}

	if _, _, err := discovery.Run(context.Background(), req); err != nil {
		t.Fatalf("first Run() failed: %v", err)
	}
	firstPage, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil || len(firstPage.Items) != 1 {
		t.Fatalf("List() = %v, %v; want exactly 1 asset", firstPage, err)
	}
	assetID := firstPage.Items[0].ID

	firstEndpoints, err := assets.ListEndpoints(context.Background(), endpointFilter(assetID))
	if err != nil || len(firstEndpoints.Items) != 1 {
		t.Fatalf("ListEndpoints() = %v, %v; want exactly 1 endpoint", firstEndpoints, err)
	}
	firstHash := firstEndpoints.Items[0].ResponseHash
	firstEndpointID := firstEndpoints.Items[0].ID

	// Change the fixture's response — same logical endpoint, different
	// content.
	fixture.SetModelsResponse(map[string]any{
		"object": "list",
		"data":   []any{map[string]any{"id": "a-different-test-model", "object": "model", "created": 1800000000}},
	})

	if _, _, err := discovery.Run(context.Background(), req); err != nil {
		t.Fatalf("second Run() failed: %v", err)
	}

	secondPage, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil || len(secondPage.Items) != 1 {
		t.Fatalf("expected the response change to still resolve to 1 asset (not create a second logical endpoint), got %v, %v", secondPage, err)
	}
	if secondPage.Items[0].ID != assetID {
		t.Fatalf("response change created a different asset: %v vs %v", assetID, secondPage.Items[0].ID)
	}

	secondEndpoints, err := assets.ListEndpoints(context.Background(), endpointFilter(assetID))
	if err != nil || len(secondEndpoints.Items) != 1 {
		t.Fatalf("expected exactly 1 endpoint after the response change, got %v, %v", secondEndpoints, err)
	}
	if secondEndpoints.Items[0].ID != firstEndpointID {
		t.Fatalf("response change created a new endpoint row instead of updating the existing one: %v vs %v", firstEndpointID, secondEndpoints.Items[0].ID)
	}
	if secondEndpoints.Items[0].ResponseHash == firstHash {
		t.Error("expected ResponseHash to change after the fixture's response changed")
	}

	evidence, err := assets.ListEvidence(context.Background(), assetrepo.EvidenceListFilter{AssetID: assetID})
	if err != nil {
		t.Fatalf("ListEvidence() failed: %v", err)
	}
	if len(evidence.Items) < 2 {
		t.Errorf("expected at least 2 evidence records (original + changed response), got %d — historical evidence must remain available", len(evidence.Items))
	}
}

func TestDiscoveryPersistence_UnauthorizedTargetRefused(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	fixture := httpfixture.New()
	defer fixture.Close()

	// Created but never authorized — starts UNVERIFIED.
	target, err := targets.Create(context.Background(), targetsvc.CreateInput{
		Name: "unauthorized fixture", Type: domaintarget.TypeURL, Value: fixture.URL(),
	})
	if err != nil {
		t.Fatalf("creating target: %v", err)
	}

	_, _, err = discovery.Run(context.Background(), discoverysvc.Request{
		TargetType: domaintarget.TypeURL, TargetValue: fixture.URL(), Config: discoveryTestConfig([]string{"/"}),
	})
	if err == nil {
		t.Fatal("expected Run() to refuse an unauthorized target")
	}

	page, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("expected no assets to be persisted for a refused (unauthorized) scan, got %d", len(page.Items))
	}
}

func TestDiscoveryPersistence_FailedEndpointsDoNotStopOthers(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	fixture := httpfixture.New()
	defer fixture.Close()

	target := createAuthorizedFixtureTarget(t, targets, fixture)
	paths := []string{"/health", "/large-response", "/error"}
	summary, _, err := discovery.Run(context.Background(), discoverysvc.Request{
		TargetType: domaintarget.TypeURL, TargetValue: fixture.URL(), Config: discoveryTestConfig(paths),
	})
	if err != nil {
		t.Fatalf("Run() failed: %v", err)
	}

	// /large-response exceeds the configured MaxResponseSize (a transport
	// failure); /error returns HTTP 500 (a completed, successful request
	// from the discovery engine's perspective — 5xx is not a transport
	// error). Neither should prevent /health from succeeding.
	if summary.Successful != 2 {
		t.Errorf("Successful = %d, want 2 (/health, /error) — results: %+v", summary.Successful, summary.Results)
	}
	if summary.Failed != 1 {
		t.Errorf("Failed = %d, want 1 (/large-response)", summary.Failed)
	}

	page, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	// /health and /error both completed successfully at the transport
	// level and should be persisted as assets; /large-response must not
	// be.
	if len(page.Items) != 2 {
		t.Fatalf("expected 2 persisted assets (health, error), got %d: %+v", len(page.Items), page.Items)
	}
}

func TestDiscoveryPersistence_ScopedRedirectFollowedWithinScope(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	fixture := httpfixture.New()
	defer fixture.Close()

	target := createAuthorizedFixtureTarget(t, targets, fixture)
	// The fixture's /redirect defaults to an in-scope redirect back to
	// its own root.
	summary, _, err := discovery.Run(context.Background(), discoverysvc.Request{
		TargetType: domaintarget.TypeURL, TargetValue: fixture.URL(), Config: discoveryTestConfig([]string{"/redirect"}),
	})
	if err != nil {
		t.Fatalf("Run() failed: %v", err)
	}
	if summary.Successful != 1 {
		t.Fatalf("expected the in-scope redirect to be followed successfully, got successful=%d: %+v", summary.Successful, summary.Results)
	}
	if summary.Redirects != 1 {
		t.Errorf("expected 1 redirect recorded, got %d", summary.Redirects)
	}

	page, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("expected the followed redirect to persist as 1 asset, got %d", len(page.Items))
	}
}

func endpointFilter(assetID uuid.UUID) endpointrepo.ListFilter {
	return endpointrepo.ListFilter{AssetID: assetID}
}
