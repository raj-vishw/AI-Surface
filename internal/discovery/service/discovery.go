// Package service orchestrates HTTP discovery end-to-end: it loads and
// authorizes the target (Phase 2 TargetService), runs
// internal/discovery/http's scanner, and normalizes/persists every
// successful result through Phase 2's AssetService — the
// "Discovery source -> Service layer -> Repository -> PostgreSQL"
// architecture phase2.md §3 established, now with a real discovery source
// on top of it.
package service

import (
	"context"
	"fmt"
	"log/slog"
	stdhttp "net/http"
	"net/url"
	"strconv"

	"github.com/google/uuid"

	discoveryhttp "ai-recon-platform/internal/discovery/http"
	"ai-recon-platform/internal/discovery/model"
	domainasset "ai-recon-platform/internal/domain/asset"
	domainendpoint "ai-recon-platform/internal/domain/endpoint"
	domaintarget "ai-recon-platform/internal/domain/target"
	apperrors "ai-recon-platform/internal/errors"
	assetsvc "ai-recon-platform/internal/service/asset"
	targetsvc "ai-recon-platform/internal/service/target"
)

// discoverySource is the fixed evidence/asset Source attribution for
// everything this package persists (see internal/domain/asset's Source
// vocabulary, phase2.md §12).
const discoverySource = "http"

// existenceConfidence is the Asset.Confidence recorded for every
// successfully-observed HTTP endpoint: a completed HTTP response is very
// strong (though not certain, hence not 1.0) evidence the endpoint exists.
// This is deliberately independent of the AI-candidate confidence score,
// which answers a different question ("how AI-related does this look")
// and is stored separately in metadata — conflating the two would
// understate existence confidence for a low-AI-confidence ordinary page,
// or overstate it for a low-existence-confidence AI-shaped response.
const existenceConfidence = domainasset.Confidence(0.9)

// supportedTargetTypes are the target types HTTP discovery accepts
// (phase3.md §8) — anything else is rejected before any request is sent.
var supportedTargetTypes = map[domaintarget.Type]bool{
	domaintarget.TypeURL:    true,
	domaintarget.TypeHost:   true,
	domaintarget.TypeDomain: true,
}

// Service is the HTTP discovery orchestrator.
type Service struct {
	targets *targetsvc.Service
	assets  *assetsvc.Service
	logger  *slog.Logger
}

// NewService builds a Service backed by targets/assets (Phase 2's
// services — no second database connection or repository layer is
// created).
func NewService(targets *targetsvc.Service, assets *assetsvc.Service, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{targets: targets, assets: assets, logger: logger}
}

// Request describes one discovery run.
type Request struct {
	// TargetType/TargetValue identify an existing, already-authorized
	// target (phase3.md §7) — Run never creates or authorizes a target
	// itself.
	TargetType  domaintarget.Type
	TargetValue string
	// Profile selects a named path set from Config.Profiles ("quick",
	// "comprehensive", ...); empty uses Config.Paths directly.
	Profile string
	DryRun  bool
	Config  discoveryhttp.Config
}

// DryRunReport is returned instead of a Summary when req.DryRun is true —
// no HTTP request is made and nothing is persisted (phase3.md §45).
type DryRunReport struct {
	Target     string
	Candidates []discoveryhttp.Candidate
}

// Run loads and authorizes req's target, then either reports the
// candidate URLs that would be requested (DryRunReport, when req.DryRun)
// or executes discovery and persists every successful result through
// AssetService (*model.Summary). Exactly one of the two return values is
// non-nil on success.
func (s *Service) Run(ctx context.Context, req Request) (*model.Summary, *DryRunReport, error) {
	if !supportedTargetTypes[req.TargetType] {
		return nil, nil, apperrors.NewValidation(
			fmt.Sprintf("target type %s is not supported by HTTP discovery (only URL, HOST, DOMAIN)", req.TargetType), nil)
	}

	target, err := s.targets.GetByValue(ctx, req.TargetType, req.TargetValue)
	if err != nil {
		return nil, nil, fmt.Errorf("loading target: %w", err)
	}
	if err := target.Validate(); err != nil {
		return nil, nil, fmt.Errorf("target is invalid: %w", err)
	}
	// Authorization is checked entirely from the already-loaded Target —
	// no HTTP request is made merely to determine whether it exists
	// (phase3.md §7).
	if !target.IsAuthorized() {
		return nil, nil, apperrors.NewForbidden("target is not authorized for active discovery", nil)
	}

	scope, err := discoveryhttp.NewScopeValidator(scopeSeedURL(req.TargetType, req.TargetValue))
	if err != nil {
		return nil, nil, fmt.Errorf("building scope validator: %w", err)
	}

	paths, err := req.Config.ResolvePaths(req.Profile)
	if err != nil {
		return nil, nil, err
	}

	if req.DryRun {
		candidates, err := discoveryhttp.GenerateCandidates(req.TargetType, req.TargetValue, req.Config, paths, scope)
		if err != nil {
			return nil, nil, err
		}
		return nil, &DryRunReport{Target: req.TargetValue, Candidates: candidates}, nil
	}

	client := discoveryhttp.NewClientForScope(req.Config, scope)
	scanner := discoveryhttp.NewScanner(client, s.logger, req.Config)

	summary, err := scanner.Scan(ctx, discoveryhttp.ScanRequest{
		TargetID: target.ID, TargetType: req.TargetType, TargetValue: req.TargetValue, Paths: paths,
	}, scope)
	if err != nil {
		return nil, nil, err
	}

	for _, result := range summary.Results {
		if !result.Succeeded() {
			continue
		}
		// A persistence failure for one result must not abort the scan
		// (phase3.md §43) — the HTTP observation itself already
		// completed; log and move on to the next result.
		if err := s.persist(ctx, target.ID, result); err != nil {
			s.logger.Error("http_discovery_persist_failed",
				"scan_id", result.ScanID, "target_id", target.ID, "url", result.URL, "error", err)
		}
	}

	return summary, nil, nil
}

// persist normalizes result into a Phase 2 Asset (with HTTP_RESPONSE
// evidence recorded atomically alongside it — see AssetService.
// RecordObservation) and a corresponding Endpoint. It reuses Phase 2's
// identity/deduplication/redaction logic entirely; this package computes
// no identity or SQL of its own (phase2.md §3, phase3.md §19/§20).
func (s *Service) persist(ctx context.Context, targetID uuid.UUID, result model.Result) error {
	finalURL := result.FinalURL
	if finalURL == "" {
		finalURL = result.URL
	}

	parsed, err := url.Parse(finalURL)
	if err != nil {
		return fmt.Errorf("parsing final URL %q: %w", finalURL, err)
	}
	hostname := parsed.Hostname()
	protocol := parsed.Scheme
	port := defaultPortForScheme(protocol)
	if p := parsed.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}

	assetType := domainasset.TypeHTTPEndpoint
	switch {
	case result.AIEndpointCandidate:
		assetType = domainasset.TypeAIEndpoint
	case result.ServiceType == model.ServiceAPI || result.ServiceType == model.ServiceJSONAPI:
		assetType = domainasset.TypeAPIEndpoint
	}

	metadata := buildMetadata(result, true)
	// Evidence data deliberately excludes scan_id: EvidenceFingerprint
	// hashes this map to deduplicate identical observations (phase2.md
	// §22), and scan_id is unique to every run by design — including it
	// here would make every re-scan of an unchanged response produce a
	// brand-new evidence row forever, defeating dedup entirely. The
	// asset's own Metadata (which does carry scan_id) always reflects the
	// most recent scan regardless; that is where "which scan last
	// confirmed this" belongs (phase3.md §41).
	evidenceData := buildMetadata(result, false)
	statusCode := result.StatusCode

	asset, _, err := s.assets.RecordObservation(ctx, assetsvc.ObservationInput{
		Asset: assetsvc.Input{
			TargetID:   targetID,
			Type:       assetType,
			Hostname:   &hostname,
			Port:       &port,
			Protocol:   &protocol,
			URL:        &finalURL,
			Source:     discoverySource,
			Confidence: existenceConfidence,
			Metadata:   metadata,
			ObservedAt: result.ObservedAt,
		},
		EvidenceType: domainasset.EvidenceHTTPResponse,
		EvidenceData: evidenceData,
	})
	if err != nil {
		return fmt.Errorf("recording asset observation: %w", err)
	}

	if _, _, err := s.assets.UpsertEndpoint(ctx, assetsvc.EndpointInput{
		AssetID:      asset.ID,
		URL:          finalURL,
		Method:       domainendpoint.Method(result.Method),
		ContentType:  result.ContentType,
		StatusCode:   &statusCode,
		ResponseHash: result.ResponseHash,
		Metadata:     metadata,
		ObservedAt:   result.ObservedAt,
	}); err != nil {
		return fmt.Errorf("upserting endpoint: %w", err)
	}

	return nil
}

func defaultPortForScheme(scheme string) int {
	if scheme == "https" {
		return 443
	}
	return 80
}

// scopeSeedURL builds the URL ScopeValidator needs just to extract a host
// from — the scheme is irrelevant for that purpose.
func scopeSeedURL(targetType domaintarget.Type, value string) string {
	if targetType == domaintarget.TypeURL {
		return value
	}
	return "https://" + value
}

// buildMetadata assembles the (pre-redaction — AssetService sanitizes it
// before anything is logged or stored) response metadata attached to the
// asset/endpoint rows and, when includeScanID is false, the evidence
// record. includeScanID controls only the "scan_id" field — see persist's
// call sites for why evidence deliberately omits it while the asset/
// endpoint rows include it.
func buildMetadata(result model.Result, includeScanID bool) map[string]any {
	metadata := map[string]any{
		"status_code":             result.StatusCode,
		"content_type":            result.ContentType,
		"response_hash":           result.ResponseHash,
		"service_type":            string(result.ServiceType),
		"ai_endpoint_candidate":   result.AIEndpointCandidate,
		"ai_candidate_confidence": result.Confidence,
		"discovery_method":        "http",
	}
	if includeScanID {
		metadata["scan_id"] = result.ScanID.String()
	}
	if len(result.Indicators) > 0 {
		indicators := make([]any, len(result.Indicators))
		for i, v := range result.Indicators {
			indicators[i] = v
		}
		metadata["indicators"] = indicators
	}
	if server := headerValue(result.Headers, "Server"); server != "" {
		metadata["server"] = server
	}
	if result.TLSMetadata != nil {
		metadata["tls_version"] = result.TLSMetadata.Version
		metadata["tls_cipher_suite"] = result.TLSMetadata.CipherSuite
	}
	if len(result.RedirectChain) > 0 {
		chain := make([]any, len(result.RedirectChain))
		for i, v := range result.RedirectChain {
			chain[i] = v
		}
		metadata["redirect_chain"] = chain
	}
	return metadata
}

func headerValue(headers map[string][]string, key string) string {
	values := headers[stdhttp.CanonicalHeaderKey(key)]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
