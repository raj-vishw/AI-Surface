//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/database"
	detectionengine "ai-recon-platform/internal/detection"
	"ai-recon-platform/internal/detection/detectors"
	domainasset "ai-recon-platform/internal/domain/asset"
	domainendpoint "ai-recon-platform/internal/domain/endpoint"
	domainfinding "ai-recon-platform/internal/domain/finding"
	domaintarget "ai-recon-platform/internal/domain/target"
	findingrepo "ai-recon-platform/internal/repository/finding"
	fingerprintrepo "ai-recon-platform/internal/repository/fingerprint"
	assetsvc "ai-recon-platform/internal/service/asset"
	detectionsvc "ai-recon-platform/internal/service/detection"
	targetsvc "ai-recon-platform/internal/service/target"
)

func findingTestTarget(t *testing.T, targets *targetsvc.Service, value string, authorized bool) domaintarget.Target {
	t.Helper()
	ctx := context.Background()
	target, err := targets.Create(ctx, targetsvc.CreateInput{
		Name: "finding fixture " + uniqueValue("finding"), Type: domaintarget.TypeURL, Value: value,
	})
	if err != nil {
		t.Fatalf("creating target: %v", err)
	}
	if !authorized {
		return target
	}
	result, err := targets.UpdateAuthorizationStatus(ctx, target.ID, domaintarget.AuthorizationAuthorized)
	if err != nil {
		t.Fatalf("authorizing target: %v", err)
	}
	return result
}

// upsertHTTPEndpointAsset creates an HTTP_ENDPOINT asset + one GET
// endpoint whose Metadata mirrors what internal/discovery/service/
// discovery.go's buildMetadata actually produces (discovery_method=http),
// with an overridable headers map — the exact shape Phase 8's
// security-header detectors read.
func upsertHTTPEndpointAsset(t *testing.T, assets *assetsvc.Service, targetID uuid.UUID, url string, headers map[string]any) (domainasset.Asset, domainendpoint.Endpoint) {
	t.Helper()
	ctx := context.Background()

	metadata := map[string]any{
		"status_code": 200, "content_type": "text/html", "discovery_method": "http",
	}
	if len(headers) > 0 {
		metadata["headers"] = headers
	}

	asset, _, err := assets.UpsertAsset(ctx, assetsvc.Input{
		TargetID: targetID, Type: domainasset.TypeHTTPEndpoint, URL: &url,
		Source: "http", Confidence: 0.9, Metadata: metadata,
	})
	if err != nil {
		t.Fatalf("upserting asset: %v", err)
	}

	statusCode := 200
	endpoint, _, err := assets.UpsertEndpoint(ctx, assetsvc.EndpointInput{
		AssetID: asset.ID, URL: url, Method: domainendpoint.MethodGet, ContentType: "text/html",
		StatusCode: &statusCode, Classification: domainendpoint.ClassificationPage,
		Observed: true, Confidence: 0.9, Metadata: metadata,
	})
	if err != nil {
		t.Fatalf("upserting endpoint: %v", err)
	}
	return asset, endpoint
}

func buildFindingService(t *testing.T, pool *database.Pool) *detectionsvc.Service {
	t.Helper()
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	fingerprints := fingerprintrepo.NewPostgresRepository(pool)
	registry := detectionengine.NewRegistry()
	if err := detectors.RegisterAll(registry, nil); err != nil {
		t.Fatalf("registering detectors: %v", err)
	}
	return detectionsvc.NewService(pool, targets, assets, fingerprints, registry, nil)
}

func TestFindingPersistence_EndToEnd(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	svc := buildFindingService(t, pool)

	target := findingTestTarget(t, targets, "https://"+uniqueValue("assetless"), false)
	upsertHTTPEndpointAsset(t, assets, target.ID, target.Value+"/", nil)

	result, dryRun, err := svc.Run(context.Background(), detectionsvc.Request{
		TargetType: domaintarget.TypeURL, TargetValue: target.Value, Mode: detectionengine.ModePassive,
	})
	if err != nil {
		t.Fatalf("Run() failed: %v", err)
	}
	if dryRun != nil {
		t.Fatal("expected a real run, not a dry-run report")
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected at least one finding (missing HSTS/CSP/etc on a header-less HTTPS response)")
	}

	var foundHSTS bool
	for _, f := range result.Findings {
		if f.DetectorID == "security_headers.missing-hsts" {
			foundHSTS = true
			if f.Status != domainfinding.StatusOpen {
				t.Errorf("expected a brand-new finding to be open, got %s", f.Status)
			}
			if f.Scope != domainfinding.ScopeEndpoint || f.EndpointID == nil {
				t.Errorf("expected HSTS finding to be endpoint-scoped, got scope=%s endpoint_id=%v", f.Scope, f.EndpointID)
			}
		}
	}
	if !foundHSTS {
		t.Fatal("expected a missing-HSTS finding")
	}
}

func TestFindingPersistence_LifecycleResolvedThenReopened(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	svc := buildFindingService(t, pool)

	target := findingTestTarget(t, targets, "https://"+uniqueValue("lifecycle"), false)
	url := target.Value + "/"

	// Scan 1: missing CSP -> open.
	upsertHTTPEndpointAsset(t, assets, target.ID, url, nil)
	result1, _, err := svc.Run(context.Background(), detectionsvc.Request{TargetType: domaintarget.TypeURL, TargetValue: target.Value, Mode: detectionengine.ModePassive})
	if err != nil {
		t.Fatalf("scan 1 failed: %v", err)
	}
	cspID := findFindingID(t, result1.Findings, "security_headers.csp")
	assertStatus(t, svc, cspID, domainfinding.StatusOpen)

	// Scan 2: CSP now present -> resolved.
	upsertHTTPEndpointAsset(t, assets, target.ID, url, map[string]any{"Content-Security-Policy": "default-src 'self'"})
	if _, _, err := svc.Run(context.Background(), detectionsvc.Request{TargetType: domaintarget.TypeURL, TargetValue: target.Value, Mode: detectionengine.ModePassive}); err != nil {
		t.Fatalf("scan 2 failed: %v", err)
	}
	assertStatus(t, svc, cspID, domainfinding.StatusResolved)

	// Scan 3: CSP missing again -> reopened.
	upsertHTTPEndpointAsset(t, assets, target.ID, url, nil)
	result3, _, err := svc.Run(context.Background(), detectionsvc.Request{TargetType: domaintarget.TypeURL, TargetValue: target.Value, Mode: detectionengine.ModePassive})
	if err != nil {
		t.Fatalf("scan 3 failed: %v", err)
	}
	cspID3 := findFindingID(t, result3.Findings, "security_headers.csp")
	if cspID3 != cspID {
		t.Fatalf("expected the same finding identity to be reused (id %s), got a different id %s", cspID, cspID3)
	}
	assertStatus(t, svc, cspID, domainfinding.StatusReopened)
}

func TestFindingPersistence_DryRunPersistsNothing(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	svc := buildFindingService(t, pool)

	target := findingTestTarget(t, targets, "https://"+uniqueValue("dryrun"), false)
	upsertHTTPEndpointAsset(t, assets, target.ID, target.Value+"/", nil)

	result, dryRun, err := svc.Run(context.Background(), detectionsvc.Request{
		TargetType: domaintarget.TypeURL, TargetValue: target.Value, Mode: detectionengine.ModePassive, DryRun: true,
	})
	if err != nil {
		t.Fatalf("Run() failed: %v", err)
	}
	if result != nil {
		t.Fatal("expected no RunResult for a dry run")
	}
	if dryRun == nil || dryRun.NetworkRequests != 0 {
		t.Fatalf("expected a dry-run report with 0 network requests, got %#v", dryRun)
	}
	if len(dryRun.EnabledDetectors) == 0 {
		t.Fatal("expected the dry-run report to list enabled detectors")
	}

	page, err := svc.List(context.Background(), findingrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("expected zero persisted findings after a dry run, got %d", len(page.Items))
	}
}

func TestFindingPersistence_SafeActiveRequiresAuthorization(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	svc := buildFindingService(t, pool)

	target := findingTestTarget(t, targets, "https://"+uniqueValue("unauthorized"), false) // never authorized

	_, _, err := svc.Run(context.Background(), detectionsvc.Request{
		TargetType: domaintarget.TypeURL, TargetValue: target.Value, Mode: detectionengine.ModeSafeActive,
	})
	if err == nil {
		t.Fatal("expected safe-active mode to be refused for an unauthorized target")
	}
}

func TestFindingPersistence_PassiveModeAllowedWithoutAuthorization(t *testing.T) {
	// Passive analysis reads only already-persisted evidence and issues no
	// request of its own — it is not gated by target authorization,
	// mirroring Phase 6's fingerprint command (phase8.md §13's boundary
	// applies to *active* operations).
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	svc := buildFindingService(t, pool)

	target := findingTestTarget(t, targets, "https://"+uniqueValue("passiveunauth"), false)
	upsertHTTPEndpointAsset(t, assets, target.ID, target.Value+"/", nil)

	_, _, err := svc.Run(context.Background(), detectionsvc.Request{
		TargetType: domaintarget.TypeURL, TargetValue: target.Value, Mode: detectionengine.ModePassive,
	})
	if err != nil {
		t.Fatalf("expected passive mode to succeed without authorization, got: %v", err)
	}
}

func TestFindingPersistence_SafeActiveGitExposure(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/HEAD" {
			_, _ = w.Write([]byte("ref: refs/heads/main\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer fixture.Close()

	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	svc := buildFindingService(t, pool)

	target := findingTestTarget(t, targets, fixture.URL, true)
	upsertHTTPEndpointAsset(t, assets, target.ID, fixture.URL+"/", nil)

	result, _, err := svc.Run(context.Background(), detectionsvc.Request{
		TargetType: domaintarget.TypeURL, TargetValue: fixture.URL, Mode: detectionengine.ModeSafeActive,
		Config: detectionengine.Config{RequestTimeout: 5 * time.Second, MaxResponseSize: 65536},
	})
	if err != nil {
		t.Fatalf("Run() failed: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.DetectorID == "exposed_files.git-exposure" {
			found = true
			if f.Severity != domainfinding.SeverityHigh {
				t.Errorf("expected high severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected a git-exposure finding from the safe-active check")
	}
}

func findFindingID(t *testing.T, findings []domainfinding.Finding, detectorID string) uuid.UUID {
	t.Helper()
	for _, f := range findings {
		if f.DetectorID == detectorID {
			return f.ID
		}
	}
	t.Fatalf("no finding from detector %q", detectorID)
	return uuid.Nil
}

func assertStatus(t *testing.T, svc *detectionsvc.Service, id uuid.UUID, want domainfinding.Status) {
	t.Helper()
	f, err := svc.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("GetByID(%s) failed: %v", id, err)
	}
	if f.Status != want {
		t.Fatalf("finding %s status = %s, want %s", id, f.Status, want)
	}
}
