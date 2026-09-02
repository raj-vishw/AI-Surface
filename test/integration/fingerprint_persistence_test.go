//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	discoverysvc "ai-recon-platform/internal/discovery/service"
	domainasset "ai-recon-platform/internal/domain/asset"
	domainfp "ai-recon-platform/internal/domain/fingerprint"
	domaintarget "ai-recon-platform/internal/domain/target"
	fpengine "ai-recon-platform/internal/fingerprint"
	assetrepo "ai-recon-platform/internal/repository/asset"
	fingerprintrepo "ai-recon-platform/internal/repository/fingerprint"
	assetsvc "ai-recon-platform/internal/service/asset"
	fingerprintsvc "ai-recon-platform/internal/service/fingerprint"
	targetsvc "ai-recon-platform/internal/service/target"
	httpfixture "ai-recon-platform/test/fixtures/http"
)

// mustEngine builds the fingerprint engine from the platform's built-in
// signature set — the same set the real CLI uses, never a test-only
// reduced one, so these tests exercise the real signatures.
func mustEngine(t *testing.T) *fpengine.Engine {
	t.Helper()
	sigs, err := fpengine.LoadDefaultSignatures()
	if err != nil {
		t.Fatalf("LoadDefaultSignatures: %v", err)
	}
	return fpengine.NewEngine(sigs, fpengine.EngineConfig{MinConfidence: 0})
}

// scanFingerprintFixture runs a real Phase 3 HTTP scan against fixture's
// /fingerprint-target endpoint and returns the resulting HTTP_ENDPOINT
// asset — real, persisted evidence for the fingerprint engine to analyze,
// not a synthetic Observation built by hand.
func scanFingerprintFixture(t *testing.T, discovery *discoverysvc.Service, targets *targetsvc.Service, assets *assetsvc.Service, fixture *httpfixture.Server) domainasset.Asset {
	t.Helper()
	ctx := context.Background()

	target := createAuthorizedFixtureTarget(t, targets, fixture)
	summary, _, err := discovery.Run(ctx, discoverysvc.Request{
		TargetType: domaintarget.TypeURL, TargetValue: fixture.URL(),
		Config: discoveryTestConfig([]string{"/fingerprint-target"}),
	})
	if err != nil {
		t.Fatalf("Run() failed: %v", err)
	}
	if summary.Successful != 1 {
		t.Fatalf("expected the HTTP scan to succeed, got %+v", summary)
	}

	page, err := assets.List(ctx, assetrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("expected exactly 1 asset from the scan, got %d", len(page.Items))
	}
	return page.Items[0]
}

func TestFingerprintPersistence_EndToEnd(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)
	fingerprints := fingerprintsvc.NewService(pool, assets, mustEngine(t), nil, fingerprintsvc.Config{})

	fixture := httpfixture.New()
	defer fixture.Close()
	fixture.SetFingerprintServerHeader("nginx/1.25.3")

	asset := scanFingerprintFixture(t, discovery, targets, assets, fixture)

	scanID := uuid.New()
	result, err := fingerprints.Analyze(context.Background(), asset.ID, &scanID, false)
	if err != nil {
		t.Fatalf("Analyze() failed: %v", err)
	}

	nginx := findFingerprintResult(t, result.Results, "nginx")
	if nginx.Category != fpengine.CategoryWebServer {
		t.Errorf("nginx category = %s, want web_server", nginx.Category)
	}
	if nginx.Version != "1.25.3" {
		t.Errorf("nginx version = %q, want 1.25.3", nginx.Version)
	}
	express := findFingerprintResult(t, result.Results, "Express")
	if express.Category != fpengine.CategoryFramework {
		t.Errorf("Express category = %s, want framework", express.Category)
	}

	// Change detection: a first-ever analysis reports everything as "added".
	if len(result.Changes) < 2 {
		t.Errorf("expected at least 2 'added' changes on first analysis, got %+v", result.Changes)
	}
	for _, c := range result.Changes {
		if c.Type != fingerprintsvc.ChangeAdded {
			t.Errorf("expected only 'added' changes on first analysis, got %s for %s", c.Type, c.Technology)
		}
	}

	// Persisted, queryable via the repository directly.
	page, err := fingerprints.List(context.Background(), fingerprintrepo.ListFilter{AssetID: asset.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	found := false
	var nginxRow domainfp.Fingerprint
	for _, f := range page.Items {
		if f.Technology == "nginx" {
			found = true
			nginxRow = f
		}
		if f.Status != domainfp.StatusActive {
			t.Errorf("expected every fingerprint to be ACTIVE after a fresh analysis, got %s for %s", f.Status, f.Technology)
		}
	}
	if !found {
		t.Fatal("expected a persisted nginx fingerprint")
	}

	evidencePage, err := fingerprints.ListEvidence(context.Background(), fingerprintrepo.EvidenceListFilter{FingerprintID: nginxRow.ID})
	if err != nil {
		t.Fatalf("ListEvidence() failed: %v", err)
	}
	if len(evidencePage.Items) != 1 {
		t.Fatalf("expected exactly 1 evidence entry after the first analysis, got %d", len(evidencePage.Items))
	}
	if len(evidencePage.Items[0].Signals) == 0 {
		t.Error("expected the evidence entry to carry at least one signal")
	}
}

func TestFingerprintPersistence_IdempotentReanalysis(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)
	fingerprints := fingerprintsvc.NewService(pool, assets, mustEngine(t), nil, fingerprintsvc.Config{})

	fixture := httpfixture.New()
	defer fixture.Close()
	fixture.SetFingerprintServerHeader("nginx/1.25.3")

	asset := scanFingerprintFixture(t, discovery, targets, assets, fixture)

	scanID := uuid.New()
	first, err := fingerprints.Analyze(context.Background(), asset.ID, &scanID, false)
	if err != nil {
		t.Fatalf("first Analyze() failed: %v", err)
	}
	firstNginx := findFingerprintResult(t, first.Results, "nginx")

	firstPage, err := fingerprints.List(context.Background(), fingerprintrepo.ListFilter{AssetID: asset.ID, Technology: "nginx"})
	if err != nil || len(firstPage.Items) != 1 {
		t.Fatalf("List() after first analysis: %v, items=%d", err, len(firstPage.Items))
	}
	firstRow := firstPage.Items[0]

	time.Sleep(10 * time.Millisecond)

	scanID2 := uuid.New()
	second, err := fingerprints.Analyze(context.Background(), asset.ID, &scanID2, false)
	if err != nil {
		t.Fatalf("second Analyze() failed: %v", err)
	}
	secondNginx := findFingerprintResult(t, second.Results, "nginx")
	if secondNginx.Confidence != firstNginx.Confidence {
		t.Errorf("confidence changed across an idempotent re-analysis: %v -> %v", firstNginx.Confidence, secondNginx.Confidence)
	}

	// No changes reported for unchanged evidence.
	for _, c := range second.Changes {
		if c.Technology == "nginx" {
			t.Errorf("expected no change reported for nginx on an idempotent re-analysis, got %+v", c)
		}
	}

	secondPage, err := fingerprints.List(context.Background(), fingerprintrepo.ListFilter{AssetID: asset.ID, Technology: "nginx"})
	if err != nil || len(secondPage.Items) != 1 {
		t.Fatalf("List() after second analysis: %v, items=%d", err, len(secondPage.Items))
	}
	secondRow := secondPage.Items[0]

	if secondRow.ID != firstRow.ID {
		t.Fatalf("re-analysis created a new fingerprint row: %v vs %v", firstRow.ID, secondRow.ID)
	}
	if !secondRow.FirstSeen.Equal(firstRow.FirstSeen) {
		t.Errorf("FirstSeen changed across re-analysis: %v -> %v", firstRow.FirstSeen, secondRow.FirstSeen)
	}
	if !secondRow.LastSeen.After(firstRow.LastSeen) {
		t.Errorf("LastSeen did not advance across re-analysis: %v -> %v", firstRow.LastSeen, secondRow.LastSeen)
	}

	evidencePage, err := fingerprints.ListEvidence(context.Background(), fingerprintrepo.EvidenceListFilter{FingerprintID: secondRow.ID})
	if err != nil {
		t.Fatalf("ListEvidence() failed: %v", err)
	}
	if len(evidencePage.Items) != 1 {
		t.Errorf("expected evidence count to hold at 1 for unchanged signals, got %d", len(evidencePage.Items))
	}
}

func TestFingerprintPersistence_VersionChangeDetected(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)
	fingerprints := fingerprintsvc.NewService(pool, assets, mustEngine(t), nil, fingerprintsvc.Config{})

	fixture := httpfixture.New()
	defer fixture.Close()
	fixture.SetFingerprintServerHeader("nginx/1.24.0")

	asset := scanFingerprintFixture(t, discovery, targets, assets, fixture)
	scanID := uuid.New()
	if _, err := fingerprints.Analyze(context.Background(), asset.ID, &scanID, false); err != nil {
		t.Fatalf("first Analyze() failed: %v", err)
	}

	// Simulate an upgrade, then re-scan (Phase 3) and re-analyze (Phase 6).
	fixture.SetFingerprintServerHeader("nginx/1.25.3")
	asset = scanFingerprintFixture(t, discovery, targets, assets, fixture)

	scanID2 := uuid.New()
	second, err := fingerprints.Analyze(context.Background(), asset.ID, &scanID2, false)
	if err != nil {
		t.Fatalf("second Analyze() failed: %v", err)
	}

	found := false
	for _, c := range second.Changes {
		if c.Technology == "nginx" && c.Type == fingerprintsvc.ChangeVersionChanged {
			found = true
			if c.PreviousVersion != "1.24.0" || c.CurrentVersion != "1.25.3" {
				t.Errorf("versions = %q -> %q, want 1.24.0 -> 1.25.3", c.PreviousVersion, c.CurrentVersion)
			}
		}
	}
	if !found {
		t.Fatalf("expected a version_changed change for nginx, got %+v", second.Changes)
	}

	// Historical evidence preserved: both the old and new Server-header
	// signal values are present as separate evidence rows.
	page, err := fingerprints.List(context.Background(), fingerprintrepo.ListFilter{AssetID: asset.ID, Technology: "nginx"})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("List(): %v, items=%d", err, len(page.Items))
	}
	evidencePage, err := fingerprints.ListEvidence(context.Background(), fingerprintrepo.EvidenceListFilter{FingerprintID: page.Items[0].ID})
	if err != nil {
		t.Fatalf("ListEvidence() failed: %v", err)
	}
	if len(evidencePage.Items) != 2 {
		t.Fatalf("expected 2 evidence entries (old + new signal sets preserved), got %d", len(evidencePage.Items))
	}
}

func TestFingerprintPersistence_RemovedFingerprintMarkedInactiveNotDeleted(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)
	fingerprints := fingerprintsvc.NewService(pool, assets, mustEngine(t), nil, fingerprintsvc.Config{})

	fixture := httpfixture.New()
	defer fixture.Close()
	fixture.SetFingerprintServerHeader("nginx/1.25.3")

	asset := scanFingerprintFixture(t, discovery, targets, assets, fixture)
	scanID := uuid.New()
	if _, err := fingerprints.Analyze(context.Background(), asset.ID, &scanID, false); err != nil {
		t.Fatalf("first Analyze() failed: %v", err)
	}

	page, err := fingerprints.List(context.Background(), fingerprintrepo.ListFilter{AssetID: asset.ID, Technology: "nginx"})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("List(): %v, items=%d", err, len(page.Items))
	}
	nginxID := page.Items[0].ID

	// Simulate nginx being replaced entirely — no Server/Via header at all.
	fixture.SetFingerprintServerHeader("")
	asset = scanFingerprintFixture(t, discovery, targets, assets, fixture)

	scanID2 := uuid.New()
	second, err := fingerprints.Analyze(context.Background(), asset.ID, &scanID2, false)
	if err != nil {
		t.Fatalf("second Analyze() failed: %v", err)
	}

	removedNginx := false
	for _, c := range second.Changes {
		if c.Technology == "nginx" && c.Type == fingerprintsvc.ChangeRemoved {
			removedNginx = true
		}
	}
	if !removedNginx {
		t.Fatalf("expected a 'removed' change for nginx, got %+v", second.Changes)
	}

	// Preserved, never deleted — just moved to INACTIVE.
	row, err := fingerprints.List(context.Background(), fingerprintrepo.ListFilter{AssetID: asset.ID, Technology: "nginx"})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(row.Items) != 1 {
		t.Fatalf("expected the nginx fingerprint row to still exist (preserved, not deleted), got %d rows", len(row.Items))
	}
	if row.Items[0].ID != nginxID {
		t.Errorf("expected the same fingerprint row id to persist: %v vs %v", nginxID, row.Items[0].ID)
	}
	if row.Items[0].Status != domainfp.StatusInactive {
		t.Errorf("Status = %s, want INACTIVE", row.Items[0].Status)
	}
}

func TestFingerprintPersistence_DryRunPersistsNothing(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)
	fingerprints := fingerprintsvc.NewService(pool, assets, mustEngine(t), nil, fingerprintsvc.Config{})

	fixture := httpfixture.New()
	defer fixture.Close()
	fixture.SetFingerprintServerHeader("nginx/1.25.3")

	asset := scanFingerprintFixture(t, discovery, targets, assets, fixture)

	scanID := uuid.New()
	result, err := fingerprints.Analyze(context.Background(), asset.ID, &scanID, true)
	if err != nil {
		t.Fatalf("Analyze(dryRun=true) failed: %v", err)
	}
	if len(result.Results) == 0 {
		t.Fatal("expected dry-run to still report evaluated results")
	}
	if len(result.Changes) != 0 {
		t.Errorf("expected no Changes in dry-run mode, got %+v", result.Changes)
	}

	page, err := fingerprints.List(context.Background(), fingerprintrepo.ListFilter{AssetID: asset.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("expected no fingerprints persisted in dry-run mode, got %d", len(page.Items))
	}
}

func TestFingerprintPersistence_NoEvidenceProducesNoFingerprints(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	fingerprints := fingerprintsvc.NewService(pool, assets, mustEngine(t), nil, fingerprintsvc.Config{})

	// A DOMAIN asset created and observed directly (bypassing any
	// discovery source), with no HTTP/DNS/network metadata at all.
	target, err := targets.Create(context.Background(), targetsvc.CreateInput{
		Name: "no-evidence fingerprint target", Type: domaintarget.TypeDomain, Value: uniqueValue("no-evidence"),
	})
	if err != nil {
		t.Fatalf("creating target: %v", err)
	}
	hostname := target.Value
	asset, _, err := assets.UpsertAsset(context.Background(), assetsvc.Input{
		TargetID: target.ID, Type: domainasset.TypeDomain, Hostname: &hostname,
		Source: "manual", Confidence: 0.5,
	})
	if err != nil {
		t.Fatalf("UpsertAsset() failed: %v", err)
	}

	scanID := uuid.New()
	result, err := fingerprints.Analyze(context.Background(), asset.ID, &scanID, false)
	if err != nil {
		t.Fatalf("Analyze() failed: %v", err)
	}
	if len(result.Results) != 0 {
		t.Errorf("expected no fingerprints from an asset with no evidence, got %+v", result.Results)
	}
}

func findFingerprintResult(t *testing.T, results []fpengine.Result, technology string) fpengine.Result {
	t.Helper()
	for _, r := range results {
		if r.Technology == technology {
			return r
		}
	}
	names := make([]string, len(results))
	for i, r := range results {
		names[i] = r.Technology
	}
	t.Fatalf("no result found for technology %q among %v", technology, names)
	return fpengine.Result{}
}
