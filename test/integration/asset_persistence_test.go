//go:build integration

package integration

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	domainasset "ai-recon-platform/internal/domain/asset"
	domainendpoint "ai-recon-platform/internal/domain/endpoint"
	domaintarget "ai-recon-platform/internal/domain/target"
	assetrepo "ai-recon-platform/internal/repository/asset"
	"ai-recon-platform/internal/repository/pagination"
	assetsvc "ai-recon-platform/internal/service/asset"
	targetsvc "ai-recon-platform/internal/service/target"
)

func strp(s string) *string { return &s }
func intp(n int) *int       { return &n }

// createTestTarget is a shared fixture: every asset test needs a real,
// persisted target row to attach assets to (assets.target_id is a foreign
// key — phase2.md §38's "foreign key violation" failure mode is exercised
// directly in TestAssetPersistence_ForeignKeyViolation below).
func createTestTarget(t *testing.T, targets *targetsvc.Service) domaintarget.Target {
	t.Helper()
	created, err := targets.Create(context.Background(), targetsvc.CreateInput{
		Name: "asset persistence fixture", Type: domaintarget.TypeDomain, Value: uniqueValue("fixture"),
	})
	if err != nil {
		t.Fatalf("creating fixture target: %v", err)
	}
	return created
}

func TestAssetPersistence_UpsertCreatesThenDeduplicates(t *testing.T) {
	pool := setupDB(t)
	assets := assetsvc.NewService(pool)
	targets := targetsvc.NewService(pool)
	ctx := context.Background()

	target := createTestTarget(t, targets)
	host := uniqueValue("host")

	first, created, err := assets.UpsertAsset(ctx, assetsvc.Input{
		TargetID: target.ID, Type: domainasset.TypeHost, Hostname: strp(host),
		Source: "dns", Confidence: 0.7,
	})
	if err != nil {
		t.Fatalf("first UpsertAsset() failed: %v", err)
	}
	if !created {
		t.Fatal("expected the first upsert to create a new row")
	}

	second, created, err := assets.UpsertAsset(ctx, assetsvc.Input{
		TargetID: target.ID, Type: domainasset.TypeHost, Hostname: strp(host),
		Source: "certificate_transparency", Confidence: 0.9,
	})
	if err != nil {
		t.Fatalf("second UpsertAsset() failed: %v", err)
	}
	if created {
		t.Fatal("expected the second upsert (same identity) to update, not create")
	}
	if second.ID != first.ID {
		t.Fatalf("expected the same asset row, got different IDs: %v vs %v", first.ID, second.ID)
	}

	page, err := assets.List(ctx, assetRepoFilter(target.ID))
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("expected exactly one deduplicated asset row, got %d", len(page.Items))
	}
}

func TestAssetPersistence_FirstSeenPreservedLastSeenAdvances(t *testing.T) {
	pool := setupDB(t)
	assets := assetsvc.NewService(pool)
	targets := targetsvc.NewService(pool)
	ctx := context.Background()

	target := createTestTarget(t, targets)
	host := uniqueValue("host")
	t1 := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	t2 := time.Now().UTC().Truncate(time.Millisecond)

	first, _, err := assets.UpsertAsset(ctx, assetsvc.Input{
		TargetID: target.ID, Type: domainasset.TypeHost, Hostname: strp(host),
		Source: "dns", Confidence: 0.5, ObservedAt: t1,
	})
	if err != nil {
		t.Fatalf("first UpsertAsset() failed: %v", err)
	}

	second, _, err := assets.UpsertAsset(ctx, assetsvc.Input{
		TargetID: target.ID, Type: domainasset.TypeHost, Hostname: strp(host),
		Source: "dns", Confidence: 0.5, ObservedAt: t2,
	})
	if err != nil {
		t.Fatalf("second UpsertAsset() failed: %v", err)
	}

	if !second.FirstSeen.Equal(first.FirstSeen) {
		t.Errorf("FirstSeen changed across upserts: %v -> %v", first.FirstSeen, second.FirstSeen)
	}
	if !second.LastSeen.After(first.LastSeen) {
		t.Errorf("LastSeen did not advance: %v -> %v", first.LastSeen, second.LastSeen)
	}
	if second.Confidence != 0.5 {
		t.Errorf("confidence = %v, want 0.5 preserved", second.Confidence)
	}
}

func TestAssetPersistence_UpsertNeverChangesStatusImplicitly(t *testing.T) {
	pool := setupDB(t)
	assets := assetsvc.NewService(pool)
	targets := targetsvc.NewService(pool)
	ctx := context.Background()

	target := createTestTarget(t, targets)
	host := uniqueValue("host")

	created, _, err := assets.UpsertAsset(ctx, assetsvc.Input{
		TargetID: target.ID, Type: domainasset.TypeHost, Hostname: strp(host), Source: "dns",
	})
	if err != nil {
		t.Fatalf("UpsertAsset() failed: %v", err)
	}

	if _, err := assets.UpdateStatus(ctx, created.ID, domainasset.StatusActive); err != nil {
		t.Fatalf("UpdateStatus() failed: %v", err)
	}

	// A later observation must not silently revert the explicit status.
	observed, _, err := assets.UpsertAsset(ctx, assetsvc.Input{
		TargetID: target.ID, Type: domainasset.TypeHost, Hostname: strp(host), Source: "dns",
	})
	if err != nil {
		t.Fatalf("second UpsertAsset() failed: %v", err)
	}
	if observed.Status != domainasset.StatusActive {
		t.Errorf("status = %q after upsert, want ACTIVE preserved", observed.Status)
	}
}

func TestAssetPersistence_RecordObservationPersistsEvidenceAtomically(t *testing.T) {
	pool := setupDB(t)
	assets := assetsvc.NewService(pool)
	targets := targetsvc.NewService(pool)
	ctx := context.Background()

	target := createTestTarget(t, targets)
	host := uniqueValue("host")

	a, ev, err := assets.RecordObservation(ctx, assetsvc.ObservationInput{
		Asset: assetsvc.Input{
			TargetID: target.ID, Type: domainasset.TypeHost, Hostname: strp(host),
			Source: "dns", Confidence: 0.6,
		},
		EvidenceType: domainasset.EvidenceDNSRecord,
		EvidenceData: map[string]any{"record_type": "A", "value": "203.0.113.10"},
	})
	if err != nil {
		t.Fatalf("RecordObservation() failed: %v", err)
	}
	if ev.AssetID != a.ID {
		t.Fatalf("evidence.AssetID = %v, want %v", ev.AssetID, a.ID)
	}

	page, err := assets.ListEvidence(ctx, evidenceFilter(a.ID))
	if err != nil {
		t.Fatalf("ListEvidence() failed: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("expected exactly one evidence row, got %d", len(page.Items))
	}
}

func TestAssetPersistence_EvidenceDeduplicatesIdenticalObservations(t *testing.T) {
	pool := setupDB(t)
	assets := assetsvc.NewService(pool)
	targets := targetsvc.NewService(pool)
	ctx := context.Background()

	target := createTestTarget(t, targets)
	host := uniqueValue("host")

	input := assetsvc.ObservationInput{
		Asset: assetsvc.Input{
			TargetID: target.ID, Type: domainasset.TypeHost, Hostname: strp(host),
			Source: "dns", Confidence: 0.6,
		},
		EvidenceType: domainasset.EvidenceDNSRecord,
		EvidenceData: map[string]any{"record_type": "A", "value": "203.0.113.10"},
	}

	a1, _, err := assets.RecordObservation(ctx, input)
	if err != nil {
		t.Fatalf("first RecordObservation() failed: %v", err)
	}
	if _, _, err := assets.RecordObservation(ctx, input); err != nil {
		t.Fatalf("second RecordObservation() failed: %v", err)
	}
	// Different evidence data (same source/type) must NOT be deduplicated
	// away — it's a new, distinct observation.
	changed := input
	changed.EvidenceData = map[string]any{"record_type": "A", "value": "203.0.113.99"}
	if _, _, err := assets.RecordObservation(ctx, changed); err != nil {
		t.Fatalf("third RecordObservation() (changed data) failed: %v", err)
	}

	page, err := assets.ListEvidence(ctx, evidenceFilter(a1.ID))
	if err != nil {
		t.Fatalf("ListEvidence() failed: %v", err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("expected 2 distinct evidence rows (identical observation deduplicated, changed one kept), got %d", len(page.Items))
	}
}

func TestAssetPersistence_MetadataRedactedBeforeStorage(t *testing.T) {
	pool := setupDB(t)
	assets := assetsvc.NewService(pool)
	targets := targetsvc.NewService(pool)
	ctx := context.Background()

	target := createTestTarget(t, targets)
	created, _, err := assets.UpsertAsset(ctx, assetsvc.Input{
		TargetID: target.ID, Type: domainasset.TypeHost, Hostname: strp(uniqueValue("host")),
		Source: "http", Metadata: map[string]any{
			"server":        "nginx",
			"authorization": "Bearer super-secret-token",
		},
	})
	if err != nil {
		t.Fatalf("UpsertAsset() failed: %v", err)
	}

	fetched, err := assets.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID() failed: %v", err)
	}
	if fetched.Metadata["authorization"] != "[REDACTED]" {
		t.Errorf("expected authorization metadata to be redacted in storage, got %v", fetched.Metadata["authorization"])
	}
	if fetched.Metadata["server"] != "nginx" {
		t.Errorf("non-sensitive metadata should survive unmodified, got %v", fetched.Metadata["server"])
	}
}

func TestAssetPersistence_EndpointUpsertAndNormalization(t *testing.T) {
	pool := setupDB(t)
	assets := assetsvc.NewService(pool)
	targets := targetsvc.NewService(pool)
	ctx := context.Background()

	target := createTestTarget(t, targets)
	created, _, err := assets.UpsertAsset(ctx, assetsvc.Input{
		TargetID: target.ID, Type: domainasset.TypeAIEndpoint, URL: strp("https://" + uniqueValue("api") + "/v1"),
		Source: "http",
	})
	if err != nil {
		t.Fatalf("UpsertAsset() failed: %v", err)
	}

	code := 200
	e1, isNew, err := assets.UpsertEndpoint(ctx, assetsvc.EndpointInput{
		AssetID: created.ID, URL: "https://EXAMPLE-endpoint.test:443/v1/chat/",
		Method: domainendpoint.MethodPost, ContentType: "application/json", StatusCode: &code,
	})
	if err != nil {
		t.Fatalf("first UpsertEndpoint() failed: %v", err)
	}
	if !isNew {
		t.Fatal("expected the first endpoint upsert to create a new row")
	}
	if e1.URL != "https://example-endpoint.test/v1/chat" {
		t.Errorf("endpoint URL not normalized as expected, got %q", e1.URL)
	}

	e2, isNew, err := assets.UpsertEndpoint(ctx, assetsvc.EndpointInput{
		AssetID: created.ID, URL: "https://example-endpoint.test/v1/chat", // same normalized URL, no trailing slash
		Method: domainendpoint.MethodPost, StatusCode: &code,
	})
	if err != nil {
		t.Fatalf("second UpsertEndpoint() failed: %v", err)
	}
	if isNew {
		t.Fatal("expected the second upsert (same normalized identity) to update, not create")
	}
	if e2.ID != e1.ID {
		t.Fatalf("expected the same endpoint row, got different IDs")
	}
}

// TestAssetPersistence_ConcurrentUpsertSameIdentity is phase2.md §39's
// required concurrency test: 50 concurrent observations of the same
// logical asset must collapse to exactly one row, with FirstSeen/LastSeen
// remaining correct.
func TestAssetPersistence_ConcurrentUpsertSameIdentity(t *testing.T) {
	pool := setupDB(t)
	assets := assetsvc.NewService(pool)
	targets := targetsvc.NewService(pool)
	ctx := context.Background()

	target := createTestTarget(t, targets)
	host := uniqueValue("concurrent")

	const workers = 50
	base := time.Now().UTC().Truncate(time.Millisecond)

	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := assets.UpsertAsset(ctx, assetsvc.Input{
				TargetID: target.ID, Type: domainasset.TypeHost, Hostname: strp(host),
				Source: "dns", Confidence: 0.5,
				ObservedAt: base.Add(time.Duration(i) * time.Millisecond),
			})
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent UpsertAsset() failed: %v", err)
	}

	page, err := assets.List(ctx, assetRepoFilter(target.ID))
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("expected exactly 1 asset after %d concurrent upserts of the same identity, got %d", workers, len(page.Items))
	}

	got := page.Items[0]
	if !got.FirstSeen.Equal(base) {
		t.Errorf("FirstSeen = %v, want the earliest observation (%v)", got.FirstSeen, base)
	}
	wantLastSeen := base.Add((workers - 1) * time.Millisecond)
	if !got.LastSeen.Equal(wantLastSeen) {
		t.Errorf("LastSeen = %v, want the latest observation (%v)", got.LastSeen, wantLastSeen)
	}
}

func TestAssetPersistence_Pagination(t *testing.T) {
	pool := setupDB(t)
	assets := assetsvc.NewService(pool)
	targets := targetsvc.NewService(pool)
	ctx := context.Background()

	target := createTestTarget(t, targets)
	const total = 5
	for i := 0; i < total; i++ {
		_, _, err := assets.UpsertAsset(ctx, assetsvc.Input{
			TargetID: target.ID, Type: domainasset.TypeHost,
			Hostname: strp(fmt.Sprintf("%d.%s", i, uniqueValue("page"))), Source: "dns",
		})
		if err != nil {
			t.Fatalf("UpsertAsset() failed: %v", err)
		}
	}

	seen := map[uuid.UUID]bool{}
	cursor := ""
	pages := 0
	for {
		filter := assetRepoFilter(target.ID)
		filter.Pagination = pagination.Params{Limit: 2, Cursor: cursor}
		page, err := assets.List(ctx, filter)
		if err != nil {
			t.Fatalf("List() failed: %v", err)
		}
		for _, item := range page.Items {
			seen[item.ID] = true
		}
		pages++
		if page.NextCursor == "" || pages > 100 {
			break
		}
		cursor = page.NextCursor
	}

	if len(seen) != total {
		t.Errorf("paginated through %d unique assets, want %d", len(seen), total)
	}
	if pages < 3 {
		t.Errorf("expected at least 3 pages of size 2 for %d items, got %d pages", total, pages)
	}
}

func TestAssetPersistence_FiltersByTypeAndStatus(t *testing.T) {
	pool := setupDB(t)
	assets := assetsvc.NewService(pool)
	targets := targetsvc.NewService(pool)
	ctx := context.Background()

	target := createTestTarget(t, targets)

	host, _, err := assets.UpsertAsset(ctx, assetsvc.Input{
		TargetID: target.ID, Type: domainasset.TypeHost, Hostname: strp(uniqueValue("filter-host")), Source: "dns",
	})
	if err != nil {
		t.Fatalf("UpsertAsset() failed: %v", err)
	}
	if _, _, err := assets.UpsertAsset(ctx, assetsvc.Input{
		TargetID: target.ID, Type: domainasset.TypeIP, IP: strp("203.0.113.50"), Source: "network",
	}); err != nil {
		t.Fatalf("UpsertAsset() failed: %v", err)
	}
	if _, err := assets.UpdateStatus(ctx, host.ID, domainasset.StatusActive); err != nil {
		t.Fatalf("UpdateStatus() failed: %v", err)
	}

	filter := assetRepoFilter(target.ID)
	filter.Type = domainasset.TypeHost
	page, err := assets.List(ctx, filter)
	if err != nil {
		t.Fatalf("List() with type filter failed: %v", err)
	}
	for _, item := range page.Items {
		if item.Type != domainasset.TypeHost {
			t.Errorf("type filter leaked a %s asset", item.Type)
		}
	}

	statusFilter := assetRepoFilter(target.ID)
	statusFilter.Status = domainasset.StatusActive
	page, err = assets.List(ctx, statusFilter)
	if err != nil {
		t.Fatalf("List() with status filter failed: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != host.ID {
		t.Errorf("expected exactly the ACTIVE host asset, got %d item(s)", len(page.Items))
	}
}

func TestAssetPersistence_ForeignKeyViolation(t *testing.T) {
	pool := setupDB(t)
	assets := assetsvc.NewService(pool)
	ctx := context.Background()

	_, _, err := assets.UpsertAsset(ctx, assetsvc.Input{
		TargetID: uuid.New(), // does not exist
		Type:     domainasset.TypeHost, Hostname: strp(uniqueValue("orphan")), Source: "dns",
	})
	if err == nil {
		t.Fatal("expected an error inserting an asset against a nonexistent target")
	}
}

func TestAssetPersistence_InvalidConfidenceRejectedByValidation(t *testing.T) {
	pool := setupDB(t)
	assets := assetsvc.NewService(pool)
	targets := targetsvc.NewService(pool)
	ctx := context.Background()

	target := createTestTarget(t, targets)
	_, _, err := assets.UpsertAsset(ctx, assetsvc.Input{
		TargetID: target.ID, Type: domainasset.TypeHost, Hostname: strp(uniqueValue("badconf")),
		Source: "dns", Confidence: 1.5,
	})
	if err == nil {
		t.Fatal("expected an error for out-of-range confidence")
	}
}

func TestAssetPersistence_InvalidPortRejectedByValidation(t *testing.T) {
	pool := setupDB(t)
	assets := assetsvc.NewService(pool)
	targets := targetsvc.NewService(pool)
	ctx := context.Background()

	target := createTestTarget(t, targets)
	_, _, err := assets.UpsertAsset(ctx, assetsvc.Input{
		TargetID: target.ID, Type: domainasset.TypePort, Hostname: strp(uniqueValue("badport")),
		Port: intp(70000), Protocol: strp("tcp"), Source: "network",
	})
	if err == nil {
		t.Fatal("expected an error for an out-of-range port")
	}
}

// TestAssetPersistence_TransactionAtomicity verifies phase2.md §28/§48:
// if recording evidence fails inside RecordObservation, the asset upsert
// is rolled back too — the operation is atomic as a whole, not "upsert
// always succeeds, evidence best-effort".
func TestAssetPersistence_TransactionAtomicity(t *testing.T) {
	pool := setupDB(t)
	assets := assetsvc.NewService(pool)
	targets := targetsvc.NewService(pool)
	ctx := context.Background()

	target := createTestTarget(t, targets)
	host := uniqueValue("txn")

	_, _, err := assets.RecordObservation(ctx, assetsvc.ObservationInput{
		Asset: assetsvc.Input{
			TargetID: target.ID, Type: domainasset.TypeHost, Hostname: strp(host), Source: "dns",
		},
		EvidenceType: "NOT_A_REAL_EVIDENCE_TYPE", // fails asset_evidence_type_check
		EvidenceData: map[string]any{"x": 1.0},
	})
	if err == nil {
		t.Fatal("expected RecordObservation to fail for an invalid evidence type")
	}

	if _, err := assets.GetByIdentity(ctx, assetsvc.Input{
		TargetID: target.ID, Type: domainasset.TypeHost, Hostname: strp(host),
	}); err == nil {
		t.Fatal("expected no asset row to exist after the transaction rolled back")
	}
}

// TestAssetPersistence_ManualScenario automates phase2.md §47's manual
// verification scenario: two independent discoveries of the same logical
// asset, from different sources with different confidence, must
// deduplicate into one asset row backed by two evidence records, with
// FirstSeen fixed at the original observation and LastSeen advanced to the
// latest.
func TestAssetPersistence_ManualScenario(t *testing.T) {
	pool := setupDB(t)
	assets := assetsvc.NewService(pool)
	targets := targetsvc.NewService(pool)
	ctx := context.Background()

	target, err := targets.Create(ctx, targetsvc.CreateInput{
		Name: "example.local", Type: domaintarget.TypeDomain, Value: uniqueValue("example-local"),
	})
	if err != nil {
		t.Fatalf("creating target: %v", err)
	}

	hostname := uniqueValue("api-example-local")
	t1 := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	t2 := time.Now().UTC().Truncate(time.Millisecond)

	first, _, err := assets.RecordObservation(ctx, assetsvc.ObservationInput{
		Asset: assetsvc.Input{
			TargetID: target.ID, Type: domainasset.TypeAIEndpoint, Hostname: strp(hostname),
			URL: strp("https://" + hostname + "/v1/chat"), Source: "http", Confidence: 0.85, ObservedAt: t1,
		},
		EvidenceType: domainasset.EvidenceHTTPResponse,
		EvidenceData: map[string]any{"status_code": 200.0},
	})
	if err != nil {
		t.Fatalf("first RecordObservation() failed: %v", err)
	}

	second, _, err := assets.RecordObservation(ctx, assetsvc.ObservationInput{
		Asset: assetsvc.Input{
			TargetID: target.ID, Type: domainasset.TypeAIEndpoint, Hostname: strp(hostname),
			URL: strp("https://" + hostname + "/v1/chat"), Source: "dns", Confidence: 0.90, ObservedAt: t2,
		},
		EvidenceType: domainasset.EvidenceDNSRecord,
		EvidenceData: map[string]any{"record_type": "A"},
	})
	if err != nil {
		t.Fatalf("second RecordObservation() failed: %v", err)
	}

	if second.ID != first.ID {
		t.Fatal("expected asset count == 1 (both observations must resolve to the same asset)")
	}
	if !second.FirstSeen.Equal(t1) {
		t.Errorf("FirstSeen = %v, want the original observation %v", second.FirstSeen, t1)
	}
	if !second.LastSeen.Equal(t2) {
		t.Errorf("LastSeen = %v, want the latest observation %v", second.LastSeen, t2)
	}

	evidence, err := assets.ListEvidence(ctx, evidenceFilter(second.ID))
	if err != nil {
		t.Fatalf("ListEvidence() failed: %v", err)
	}
	if len(evidence.Items) != 2 {
		t.Fatalf("expected 2 evidence records (one per source), got %d", len(evidence.Items))
	}
}

func assetRepoFilter(targetID uuid.UUID) assetrepo.ListFilter {
	return assetrepo.ListFilter{TargetID: targetID}
}

func evidenceFilter(assetID uuid.UUID) assetrepo.EvidenceListFilter {
	return assetrepo.EvidenceListFilter{AssetID: assetID}
}
