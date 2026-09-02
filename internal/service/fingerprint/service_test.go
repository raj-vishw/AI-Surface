package fingerprint

import (
	"testing"

	"github.com/google/uuid"

	domainfp "ai-recon-platform/internal/domain/fingerprint"
	fpengine "ai-recon-platform/internal/fingerprint"
)

func TestDetectChanges_Added(t *testing.T) {
	assetID := uuid.New()
	previous := map[string]domainfp.Fingerprint{}
	current := map[string]fpengine.Result{
		"web_server|nginx": {Category: fpengine.CategoryWebServer, Technology: "nginx", Confidence: 0.9},
	}

	changes := detectChanges(assetID, previous, current, 0.10)

	if len(changes) != 1 || changes[0].Type != ChangeAdded || changes[0].Technology != "nginx" {
		t.Fatalf("expected exactly one 'added' change for nginx, got %+v", changes)
	}
}

func TestDetectChanges_Removed(t *testing.T) {
	assetID := uuid.New()
	previous := map[string]domainfp.Fingerprint{
		"framework|Next.js": {Category: domainfp.CategoryFramework, Technology: "Next.js", Confidence: 0.9, Version: "14.2"},
	}
	current := map[string]fpengine.Result{}

	changes := detectChanges(assetID, previous, current, 0.10)

	if len(changes) != 1 || changes[0].Type != ChangeRemoved || changes[0].Technology != "Next.js" {
		t.Fatalf("expected exactly one 'removed' change for Next.js, got %+v", changes)
	}
	if changes[0].PreviousVersion != "14.2" {
		t.Errorf("PreviousVersion = %q, want 14.2", changes[0].PreviousVersion)
	}
}

func TestDetectChanges_Unchanged(t *testing.T) {
	assetID := uuid.New()
	previous := map[string]domainfp.Fingerprint{
		"web_server|nginx": {Category: domainfp.CategoryWebServer, Technology: "nginx", Confidence: 0.9, Version: "1.25.3"},
	}
	current := map[string]fpengine.Result{
		"web_server|nginx": {Category: fpengine.CategoryWebServer, Technology: "nginx", Confidence: 0.9, Version: "1.25.3"},
	}

	changes := detectChanges(assetID, previous, current, 0.10)

	if len(changes) != 0 {
		t.Errorf("expected no changes for an unchanged fingerprint, got %+v", changes)
	}
}

func TestDetectChanges_VersionChanged(t *testing.T) {
	assetID := uuid.New()
	previous := map[string]domainfp.Fingerprint{
		"web_server|nginx": {Category: domainfp.CategoryWebServer, Technology: "nginx", Confidence: 0.9, Version: "1.24.0"},
	}
	current := map[string]fpengine.Result{
		"web_server|nginx": {Category: fpengine.CategoryWebServer, Technology: "nginx", Confidence: 0.9, Version: "1.25.3"},
	}

	changes := detectChanges(assetID, previous, current, 0.10)

	if len(changes) != 1 || changes[0].Type != ChangeVersionChanged {
		t.Fatalf("expected exactly one 'version_changed' change, got %+v", changes)
	}
	if changes[0].PreviousVersion != "1.24.0" || changes[0].CurrentVersion != "1.25.3" {
		t.Errorf("versions = %q -> %q, want 1.24.0 -> 1.25.3", changes[0].PreviousVersion, changes[0].CurrentVersion)
	}
}

func TestDetectChanges_MinorConfidenceFluctuationIgnored(t *testing.T) {
	assetID := uuid.New()
	previous := map[string]domainfp.Fingerprint{
		"web_server|nginx": {Category: domainfp.CategoryWebServer, Technology: "nginx", Confidence: 0.75},
	}
	current := map[string]fpengine.Result{
		"web_server|nginx": {Category: fpengine.CategoryWebServer, Technology: "nginx", Confidence: 0.78}, // +0.03, under the 0.10 threshold
	}

	changes := detectChanges(assetID, previous, current, 0.10)

	if len(changes) != 0 {
		t.Errorf("expected a minor confidence fluctuation to be ignored, got %+v", changes)
	}
}

func TestDetectChanges_SignificantConfidenceChangeReported(t *testing.T) {
	assetID := uuid.New()
	previous := map[string]domainfp.Fingerprint{
		"web_server|nginx": {Category: domainfp.CategoryWebServer, Technology: "nginx", Confidence: 0.75},
	}
	current := map[string]fpengine.Result{
		"web_server|nginx": {Category: fpengine.CategoryWebServer, Technology: "nginx", Confidence: 0.95}, // +0.20
	}

	changes := detectChanges(assetID, previous, current, 0.10)

	if len(changes) != 1 || changes[0].Type != ChangeConfidenceChanged {
		t.Fatalf("expected exactly one 'confidence_changed' change, got %+v", changes)
	}
}

func TestConvertSignals(t *testing.T) {
	in := []fpengine.Signal{
		{Type: fpengine.SignalHTTPHeader, Field: "Server", Value: "nginx", Weight: 0.8, Description: "matches"},
	}
	out := convertSignals(in)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1", len(out))
	}
	if out[0].Type != "http_header" || out[0].Field != "Server" || out[0].Value != "nginx" || out[0].Weight != 0.8 {
		t.Errorf("convertSignals() = %+v, unexpected shape", out[0])
	}
}

func TestBuildFingerprintMetadata(t *testing.T) {
	scanID := uuid.New()
	r := fpengine.Result{
		SignatureName: "nginx", Level: fpengine.LevelHigh,
		Signals: []fpengine.Signal{{Type: fpengine.SignalHTTPHeader, Field: "Server", Value: "nginx", Weight: 0.8}},
	}
	metadata := buildFingerprintMetadata(r, &scanID)

	if metadata["signature"] != "nginx" {
		t.Errorf("signature = %v, want nginx", metadata["signature"])
	}
	if metadata["level"] != "high" {
		t.Errorf("level = %v, want high", metadata["level"])
	}
	if metadata["scan_id"] != scanID.String() {
		t.Errorf("scan_id = %v, want %v", metadata["scan_id"], scanID.String())
	}
	signals, ok := metadata["signals"].([]any)
	if !ok || len(signals) != 1 {
		t.Fatalf("signals = %v, want a 1-element slice", metadata["signals"])
	}
}

func TestApplyMetadata_HTTPFields(t *testing.T) {
	obs := fpengine.Observation{}
	metadata := map[string]any{
		"headers":      map[string]any{"X-Powered-By": "Express"},
		"server":       "nginx/1.25.3",
		"content_type": "application/json",
		"cookie_names": []any{"JSESSIONID"},
		"tls_version":  "TLS 1.3",
	}
	applyMetadata(&obs, metadata)

	if obs.Headers["X-Powered-By"] != "Express" {
		t.Errorf("Headers[X-Powered-By] = %q, want Express", obs.Headers["X-Powered-By"])
	}
	if obs.Headers["Server"] != "nginx/1.25.3" {
		t.Errorf("Headers[Server] = %q, want nginx/1.25.3", obs.Headers["Server"])
	}
	if obs.ContentType != "application/json" {
		t.Errorf("ContentType = %q, want application/json", obs.ContentType)
	}
	if len(obs.CookieNames) != 1 || obs.CookieNames[0] != "JSESSIONID" {
		t.Errorf("CookieNames = %v, want [JSESSIONID]", obs.CookieNames)
	}
	if obs.TLSVersion != "TLS 1.3" {
		t.Errorf("TLSVersion = %q, want TLS 1.3", obs.TLSVersion)
	}
}

func TestApplyMetadata_DNSFields(t *testing.T) {
	obs := fpengine.Observation{}
	metadata := map[string]any{
		"a_records":    []any{"192.0.2.10"},
		"cname_target": "backend.example.test",
	}
	applyMetadata(&obs, metadata)

	foundA, foundCNAME := false, false
	for _, r := range obs.DNSRecords {
		if r.Type == "A" && r.Value == "192.0.2.10" {
			foundA = true
		}
		if r.Type == "CNAME" && r.Value == "backend.example.test" {
			foundCNAME = true
		}
	}
	if !foundA || !foundCNAME {
		t.Errorf("DNSRecords = %+v, want an A and a CNAME entry", obs.DNSRecords)
	}
}

func TestApplyMetadata_DoesNotOverwriteExistingField(t *testing.T) {
	obs := fpengine.Observation{ContentType: "text/html"}
	applyMetadata(&obs, map[string]any{"content_type": "application/json"})
	if obs.ContentType != "text/html" {
		t.Errorf("ContentType = %q, want text/html preserved (asset's own value wins over a sibling's)", obs.ContentType)
	}
}

func TestApplyMetadata_NilMetadata(t *testing.T) {
	obs := fpengine.Observation{}
	applyMetadata(&obs, nil) // must not panic
}
