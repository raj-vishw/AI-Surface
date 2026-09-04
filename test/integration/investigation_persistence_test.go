//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"ai-recon-platform/internal/database"
	detectionengine "ai-recon-platform/internal/detection"
	domaininvestigation "ai-recon-platform/internal/domain/investigation"
	domaintarget "ai-recon-platform/internal/domain/target"
	"ai-recon-platform/internal/investigation"
	"ai-recon-platform/internal/investigation/correlation"
	"ai-recon-platform/internal/repository/pagination"
	assetsvc "ai-recon-platform/internal/service/asset"
	detectionsvc "ai-recon-platform/internal/service/detection"
	investigationsvc "ai-recon-platform/internal/service/investigation"
	targetsvc "ai-recon-platform/internal/service/target"
)

func buildInvestigationTestService(t *testing.T, pool *database.Pool) *investigationsvc.Service {
	t.Helper()
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	registry := investigation.NewRegistry()
	if err := correlation.RegisterAll(registry); err != nil {
		t.Fatalf("registering correlation rules: %v", err)
	}
	return investigationsvc.NewService(pool, targets, assets, registry, nil)
}

func TestInvestigationPersistence_CreateAttachCorrelate(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	findingsSvc := buildFindingService(t, pool)
	invSvc := buildInvestigationTestService(t, pool)

	target := findingTestTarget(t, targets, "https://"+uniqueValue("investigation"), false)
	url := target.Value + "/"
	upsertHTTPEndpointAsset(t, assets, target.ID, url, nil) // no headers -> HSTS + CSP findings

	detResult, _, err := findingsSvc.Run(context.Background(), buildDetectionRequest(target))
	if err != nil {
		t.Fatalf("running detection: %v", err)
	}
	if len(detResult.Findings) < 2 {
		t.Fatalf("expected at least 2 findings (HSTS + CSP) on the same asset, got %d", len(detResult.Findings))
	}

	inv, err := invSvc.Create(context.Background(), investigationsvc.CreateInput{
		TargetType: domaintarget.TypeURL, TargetValue: target.Value,
		Title: "Suspicious API Surface Change", CreatedBy: "analyst1",
	})
	if err != nil {
		t.Fatalf("creating investigation: %v", err)
	}
	if inv.Status != domaininvestigation.StatusNew {
		t.Errorf("expected new status, got %s", inv.Status)
	}

	for _, f := range detResult.Findings {
		if _, err := invSvc.AttachFinding(context.Background(), inv.ID, f.ID, domaininvestigation.RelationRelated, "analyst1"); err != nil {
			t.Fatalf("attaching finding %s: %v", f.ID, err)
		}
	}

	attached, err := invSvc.ListFindings(context.Background(), inv.ID)
	if err != nil {
		t.Fatalf("listing findings: %v", err)
	}
	if len(attached) != len(detResult.Findings) {
		t.Fatalf("expected %d attached findings, got %d", len(detResult.Findings), len(attached))
	}

	corrResult, dryRun, err := invSvc.Correlate(context.Background(), inv.ID, investigation.Config{}, false)
	if err != nil {
		t.Fatalf("correlating: %v", err)
	}
	if dryRun != nil {
		t.Fatal("expected a real correlation run, not a dry-run report")
	}
	foundSameAsset := false
	for _, rel := range corrResult.Relationships {
		if rel.Type == domaininvestigation.RelationshipSameAsset {
			foundSameAsset = true
			if rel.Explanation == "" {
				t.Error("expected a non-empty explanation")
			}
		}
	}
	if !foundSameAsset {
		t.Fatal("expected a same_asset relationship between the two findings sharing an asset")
	}

	timelinePage, err := invSvc.Timeline(context.Background(), inv.ID, false, pagination.Params{Limit: pagination.MaxLimit})
	if err != nil {
		t.Fatalf("loading timeline: %v", err)
	}
	if len(timelinePage.Items) < 3 { // investigation_created + 2x finding_attached (at least)
		t.Fatalf("expected at least 3 timeline events, got %d", len(timelinePage.Items))
	}
}

func TestInvestigationPersistence_DryRunPersistsNoRelationships(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	findingsSvc := buildFindingService(t, pool)
	invSvc := buildInvestigationTestService(t, pool)

	target := findingTestTarget(t, targets, "https://"+uniqueValue("dryrun-inv"), false)
	upsertHTTPEndpointAsset(t, assets, target.ID, target.Value+"/", nil)
	detResult, _, err := findingsSvc.Run(context.Background(), buildDetectionRequest(target))
	if err != nil {
		t.Fatalf("running detection: %v", err)
	}

	inv, err := invSvc.Create(context.Background(), investigationsvc.CreateInput{
		TargetType: domaintarget.TypeURL, TargetValue: target.Value, Title: "Dry run test", CreatedBy: "analyst1",
	})
	if err != nil {
		t.Fatalf("creating investigation: %v", err)
	}
	for _, f := range detResult.Findings {
		if _, err := invSvc.AttachFinding(context.Background(), inv.ID, f.ID, domaininvestigation.RelationRelated, "analyst1"); err != nil {
			t.Fatalf("attaching finding: %v", err)
		}
	}

	result, dryRunReport, err := invSvc.Correlate(context.Background(), inv.ID, investigation.Config{}, true)
	if err != nil {
		t.Fatalf("correlating: %v", err)
	}
	if result != nil {
		t.Fatal("expected no CorrelateResult for a dry run")
	}
	if dryRunReport == nil || len(dryRunReport.Rules) == 0 {
		t.Fatal("expected a dry-run report listing enabled rules")
	}

	page, err := invSvc.ListRelationships(context.Background(), inv.ID, "", pagination.Params{Limit: pagination.MaxLimit})
	if err != nil {
		t.Fatalf("listing relationships: %v", err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("expected zero persisted relationships after a dry run, got %d", len(page.Items))
	}
}

func TestInvestigationPersistence_CloseAndReopenLifecycle(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	invSvc := buildInvestigationTestService(t, pool)

	target := findingTestTarget(t, targets, "https://"+uniqueValue("lifecycle-inv"), false)
	inv, err := invSvc.Create(context.Background(), investigationsvc.CreateInput{
		TargetType: domaintarget.TypeURL, TargetValue: target.Value, Title: "Lifecycle test", CreatedBy: "analyst1",
	})
	if err != nil {
		t.Fatalf("creating investigation: %v", err)
	}

	closed, err := invSvc.Close(context.Background(), inv.ID, inv.Version, "analyst1", "false positive")
	if err != nil {
		t.Fatalf("closing: %v", err)
	}
	if closed.Status != domaininvestigation.StatusClosed || closed.ClosedAt == nil {
		t.Fatalf("expected closed status with ClosedAt set, got %#v", closed)
	}

	if _, err := invSvc.Reopen(context.Background(), inv.ID, closed.Version, "analyst2", ""); err == nil {
		t.Fatal("expected reopen without a reason to be rejected")
	}

	reopened, err := invSvc.Reopen(context.Background(), inv.ID, closed.Version, "analyst2", "new evidence surfaced")
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	if reopened.Status != domaininvestigation.StatusOpen {
		t.Fatalf("expected open status after reopen, got %s", reopened.Status)
	}
}

func TestInvestigationPersistence_OptimisticConcurrencyConflict(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	invSvc := buildInvestigationTestService(t, pool)

	target := findingTestTarget(t, targets, "https://"+uniqueValue("concurrency-inv"), false)
	inv, err := invSvc.Create(context.Background(), investigationsvc.CreateInput{
		TargetType: domaintarget.TypeURL, TargetValue: target.Value, Title: "Concurrency test", CreatedBy: "analyst1",
	})
	if err != nil {
		t.Fatalf("creating investigation: %v", err)
	}

	priority := domaininvestigation.PriorityHigh
	if _, err := invSvc.Update(context.Background(), inv.ID, investigationsvc.UpdateInput{Priority: &priority, ActorID: "analyst1"}, inv.Version); err != nil {
		t.Fatalf("first update failed: %v", err)
	}

	// Retrying with the now-stale version must fail with a conflict —
	// two analysts editing the same investigation must never silently
	// clobber each other (phase9.md §74).
	severity := domaininvestigation.SeverityHigh
	if _, err := invSvc.Update(context.Background(), inv.ID, investigationsvc.UpdateInput{Severity: &severity, ActorID: "analyst2"}, inv.Version); err == nil {
		t.Fatal("expected a conflict error when updating with a stale version")
	}
}

func TestInvestigationPersistence_NotesAndHypotheses(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	invSvc := buildInvestigationTestService(t, pool)

	target := findingTestTarget(t, targets, "https://"+uniqueValue("notes-inv"), false)
	inv, err := invSvc.Create(context.Background(), investigationsvc.CreateInput{
		TargetType: domaintarget.TypeURL, TargetValue: target.Value, Title: "Notes test", CreatedBy: "analyst1",
	})
	if err != nil {
		t.Fatalf("creating investigation: %v", err)
	}

	if _, err := invSvc.AddNote(context.Background(), inv.ID, "analyst1", "Checked the exposure finding."); err != nil {
		t.Fatalf("adding note: %v", err)
	}
	notes, err := invSvc.ListNotes(context.Background(), inv.ID)
	if err != nil || len(notes) != 1 {
		t.Fatalf("expected 1 note, got %d, err=%v", len(notes), err)
	}

	h, err := invSvc.CreateHypothesis(context.Background(), inv.ID, "Related to recent deployment", "", "analyst1")
	if err != nil {
		t.Fatalf("creating hypothesis: %v", err)
	}
	if h.Status != domaininvestigation.HypothesisProposed {
		t.Fatalf("expected proposed status, got %s", h.Status)
	}
	if _, err := invSvc.AddHypothesisEvidence(context.Background(), h.ID, domaininvestigation.EntityFinding, uuid.New(), "supporting evidence"); err != nil {
		t.Fatalf("adding hypothesis evidence: %v", err)
	}

	updated, err := invSvc.UpdateHypothesisStatus(context.Background(), h.ID, domaininvestigation.HypothesisSupported, domaininvestigation.ConfidenceMedium, "analyst1")
	if err != nil {
		t.Fatalf("updating hypothesis status: %v", err)
	}
	if updated.Status != domaininvestigation.HypothesisSupported {
		t.Fatalf("expected supported status, got %s", updated.Status)
	}
}

func TestInvestigationPersistence_ClusterSuggestAndAccept(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	findingsSvc := buildFindingService(t, pool)
	invSvc := buildInvestigationTestService(t, pool)

	target := findingTestTarget(t, targets, "https://"+uniqueValue("cluster-inv"), false)
	upsertHTTPEndpointAsset(t, assets, target.ID, target.Value+"/", nil)
	if _, _, err := findingsSvc.Run(context.Background(), buildDetectionRequest(target)); err != nil {
		t.Fatalf("running detection: %v", err)
	}

	clusters, err := invSvc.SuggestClusters(context.Background(), domaintarget.TypeURL, target.Value)
	if err != nil {
		t.Fatalf("suggesting clusters: %v", err)
	}
	if len(clusters) == 0 {
		t.Fatal("expected at least one suggested cluster from multiple open findings on the same asset")
	}
	if clusters[0].Status != domaininvestigation.ClusterSuggested {
		t.Fatalf("expected suggested status, got %s", clusters[0].Status)
	}

	inv, err := invSvc.AcceptCluster(context.Background(), clusters[0].ID, "analyst1")
	if err != nil {
		t.Fatalf("accepting cluster: %v", err)
	}
	findings, err := invSvc.ListFindings(context.Background(), inv.ID)
	if err != nil || len(findings) == 0 {
		t.Fatalf("expected the accepted investigation to have attached findings, got %d, err=%v", len(findings), err)
	}

	accepted, err := invSvc.GetCluster(context.Background(), clusters[0].ID)
	if err != nil {
		t.Fatalf("reloading cluster: %v", err)
	}
	if accepted.Status != domaininvestigation.ClusterAccepted || accepted.AcceptedInvestigationID == nil {
		t.Fatalf("expected cluster to be accepted with an investigation id, got %#v", accepted)
	}
}

// buildDetectionRequest mirrors finding_persistence_test.go's own passive
// detection run — reused here (same package) to generate real findings
// for investigation tests to attach/correlate, rather than hand-crafting
// Finding rows directly.
func buildDetectionRequest(target domaintarget.Target) detectionsvc.Request {
	return detectionsvc.Request{
		TargetType: domaintarget.TypeURL, TargetValue: target.Value, Mode: detectionengine.ModePassive,
	}
}
