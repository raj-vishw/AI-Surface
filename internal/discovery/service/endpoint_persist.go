package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	discoveryendpoint "ai-recon-platform/internal/discovery/endpoint"
	domainasset "ai-recon-platform/internal/domain/asset"
	domainendpoint "ai-recon-platform/internal/domain/endpoint"
	assetrepo "ai-recon-platform/internal/repository/asset"
	endpointrepo "ai-recon-platform/internal/repository/endpoint"
	"ai-recon-platform/internal/repository/pagination"
	assetsvc "ai-recon-platform/internal/service/asset"
)

// assetConfidenceFor is the Asset.Confidence recorded for a discovered
// endpoint's underlying asset — a completed HTTP response (Observed) is
// strong evidence the endpoint exists; a documented-only or inferred-only
// endpoint is weaker, so the asset's own confidence uses the Result's own
// Confidence directly rather than a single fixed constant (unlike Phase
// 3, where every persisted result was, by definition, an actual
// completed request).
func assetConfidenceFor(r discoveryendpoint.Result) domainasset.Confidence {
	c := domainasset.Confidence(r.Confidence)
	if err := c.Validate(); err != nil {
		return 0.5
	}
	return c
}

// persistEndpointSummary normalizes every Result into a Phase 2 asset +
// Phase 7 endpoint (+ evidence + parameters), never aborting the whole
// run over one failure (phase7.md §82/§83), and returns the map of
// (method, url) -> persisted Endpoint this run produced, plus each one's
// parameter name set — together the "current" half of change detection.
func (s *Service) persistEndpointSummary(ctx context.Context, targetID uuid.UUID, summary *discoveryendpoint.Summary) (map[string]domainendpoint.Endpoint, map[string]map[string]bool) {
	current := make(map[string]domainendpoint.Endpoint, len(summary.Results))
	currentParams := make(map[string]map[string]bool, len(summary.Results))

	for _, r := range summary.Results {
		endpoint, err := s.persistEndpointResult(ctx, targetID, summary.ScanID, r)
		if err != nil {
			s.logger.Error("endpoint_discovery_persist_failed",
				"scan_id", summary.ScanID, "target_id", targetID, "url", r.URL, "method", r.Method, "error", err)
			continue
		}
		key := endpointKey(r.Method, r.URL)
		current[key] = endpoint
		params := make(map[string]bool, len(r.Parameters))
		for _, p := range r.Parameters {
			params[p.Name] = true
		}
		currentParams[key] = params
	}
	return current, currentParams
}

func endpointKey(method, url string) string { return method + " " + url }

// persistEndpointResult upserts the asset for r's URL (Type chosen from
// its Classification/APIType — phase7.md §32/§50), then the Endpoint row
// itself with its evidence, then every observed parameter name (never a
// value — phase7.md §9/§37).
func (s *Service) persistEndpointResult(ctx context.Context, targetID uuid.UUID, scanID uuid.UUID, r discoveryendpoint.Result) (domainendpoint.Endpoint, error) {
	assetType := assetTypeFor(r)
	metadata := buildEndpointAssetMetadata(r, scanID, true)
	evidenceData := buildEndpointAssetMetadata(r, scanID, false)

	protocol := r.Scheme
	port := r.Port
	url := r.URL

	asset, _, err := s.assets.RecordObservation(ctx, assetsvc.ObservationInput{
		Asset: assetsvc.Input{
			TargetID: targetID, Type: assetType, Hostname: &r.Host, Port: &port, Protocol: &protocol,
			URL: &url, Source: endpointSource, Confidence: assetConfidenceFor(r), Metadata: metadata,
			ObservedAt: r.ObservedAt,
		},
		EvidenceType: domainasset.EvidenceHTTPResponse,
		EvidenceData: evidenceData,
	})
	if err != nil {
		return domainendpoint.Endpoint{}, fmt.Errorf("recording asset observation: %w", err)
	}

	sourceLabel := strings.Join(r.Sources, ",")
	scanIDCopy := scanID
	endpoint, _, err := s.assets.RecordEndpointObservation(ctx, assetsvc.EndpointObservationInput{
		Endpoint: assetsvc.EndpointInput{
			AssetID: asset.ID, ScanID: &scanIDCopy, URL: r.URL, Method: domainendpoint.Method(r.Method),
			ContentType: r.ContentType, ContentLength: r.ContentLength, StatusCode: r.StatusCode, ResponseHash: r.ResponseHash,
			Classification: domainendpoint.Classification(r.Classification), APIType: r.APIType, APIVersion: r.APIVersion,
			Sources: r.Sources, Confidence: r.Confidence, Documented: r.Documented, Observed: r.Observed, Inferred: r.Inferred,
			Metadata: metadata, ObservedAt: r.ObservedAt,
		},
		Source:       sourceLabel,
		EvidenceData: buildEndpointEvidenceData(r),
	})
	if err != nil {
		return domainendpoint.Endpoint{}, fmt.Errorf("recording endpoint observation: %w", err)
	}

	for _, p := range r.Parameters {
		if _, _, err := s.assets.UpsertEndpointParameter(ctx, endpointrepo.ParameterInput{
			EndpointID: endpoint.ID, Name: p.Name, Location: p.Location, ObservedAt: r.ObservedAt,
		}); err != nil {
			s.logger.Error("endpoint_parameter_persist_failed", "endpoint_id", endpoint.ID, "name", p.Name, "error", err)
		}
	}

	return endpoint, nil
}

// assetTypeFor maps a Result's classification to a Phase 2 asset type
// (phase7.md §32/§50): an AI-candidate endpoint becomes AI_ENDPOINT
// (mirroring Phase 3's own AIEndpointCandidate -> TypeAIEndpoint
// mapping), an api/graphql/openapi/swagger-classified endpoint becomes
// API_ENDPOINT, everything else becomes the general HTTP_ENDPOINT.
func assetTypeFor(r discoveryendpoint.Result) domainasset.Type {
	if r.APIType == discoveryendpoint.AIAPIType {
		return domainasset.TypeAIEndpoint
	}
	switch r.Classification {
	case discoveryendpoint.ClassAPI, discoveryendpoint.ClassGraphQL, discoveryendpoint.ClassOpenAPI, discoveryendpoint.ClassSwagger:
		return domainasset.TypeAPIEndpoint
	default:
		return domainasset.TypeHTTPEndpoint
	}
}

// buildEndpointAssetMetadata assembles the (pre-redaction) metadata
// attached to the asset/endpoint rows and, when includeScanID is false,
// the evidence record — the same includeScanID split every other phase's
// persistence uses, since scan_id is unique per run by design and would
// otherwise defeat evidence deduplication (the scan_id-in-evidence lesson
// Phase 3 learned the hard way, applied proactively here).
func buildEndpointAssetMetadata(r discoveryendpoint.Result, scanID uuid.UUID, includeScanID bool) map[string]any {
	metadata := map[string]any{
		"classification":   string(r.Classification),
		"discovery_method": "endpoint",
		"documented":       r.Documented,
		"observed":         r.Observed,
		"inferred":         r.Inferred,
	}
	if includeScanID {
		metadata["scan_id"] = scanID.String()
	}
	if r.StatusCode != nil {
		metadata["status_code"] = *r.StatusCode
	}
	if r.ContentType != "" {
		metadata["content_type"] = r.ContentType
	}
	if r.APIType != "" {
		metadata["api_type"] = r.APIType
	}
	if r.APIVersion != "" {
		metadata["api_version"] = r.APIVersion
	}
	if len(r.Sources) > 0 {
		sources := make([]any, len(r.Sources))
		for i, v := range r.Sources {
			sources[i] = v
		}
		metadata["sources"] = sources
	}
	if r.Truncated {
		metadata["truncated"] = true
	}
	if r.Error != "" {
		metadata["error"] = r.Error
	}
	return metadata
}

// buildEndpointEvidenceData builds the evidence-only payload —
// deliberately excludes scan_id (see buildEndpointAssetMetadata's doc
// comment) and folds in the per-source evidence snippets Result.Evidence
// carries, each already sanitized at the point it was captured
// (phase7.md §42: evidence is sanitized, never a complete page).
func buildEndpointEvidenceData(r discoveryendpoint.Result) map[string]any {
	data := buildEndpointAssetMetadata(r, uuid.Nil, false)
	if len(r.Evidence) > 0 {
		snippets := make(map[string]any, len(r.Evidence))
		for k, v := range r.Evidence {
			snippets[k] = v
		}
		data["evidence_snippets"] = snippets
	}
	if len(r.Parameters) > 0 {
		names := make([]any, len(r.Parameters))
		for i, p := range r.Parameters {
			names[i] = p.Name
		}
		data["parameters"] = names
	}
	return data
}

// previousEndpoints returns every currently-known endpoint for targetID's
// HTTP_ENDPOINT/API_ENDPOINT/AI_ENDPOINT assets, keyed by (method, url),
// plus each one's parameter name set — the "before this run" snapshot
// change detection compares against (phase7.md §43/§44).
func (s *Service) previousEndpoints(ctx context.Context, targetID uuid.UUID) (map[string]domainendpoint.Endpoint, map[string]map[string]bool, error) {
	previous := make(map[string]domainendpoint.Endpoint)
	previousParams := make(map[string]map[string]bool)

	assetCursor := ""
	for {
		assetPage, err := s.assets.List(ctx, assetrepo.ListFilter{
			TargetID: targetID, Pagination: pagination.Params{Limit: pagination.MaxLimit, Cursor: assetCursor},
		})
		if err != nil {
			return nil, nil, err
		}
		for _, a := range assetPage.Items {
			if a.Type != domainasset.TypeHTTPEndpoint && a.Type != domainasset.TypeAPIEndpoint && a.Type != domainasset.TypeAIEndpoint {
				continue
			}
			endpointCursor := ""
			for {
				page, err := s.assets.ListEndpoints(ctx, endpointrepo.ListFilter{
					AssetID: a.ID, Pagination: pagination.Params{Limit: pagination.MaxLimit, Cursor: endpointCursor},
				})
				if err != nil {
					return nil, nil, err
				}
				for _, e := range page.Items {
					key := endpointKey(string(e.Method), e.URL)
					previous[key] = e

					params, err := s.assets.ListEndpointParameters(ctx, e.ID)
					if err != nil {
						return nil, nil, err
					}
					names := make(map[string]bool, len(params))
					for _, p := range params {
						names[p.Name] = true
					}
					previousParams[key] = names
				}
				if page.NextCursor == "" {
					break
				}
				endpointCursor = page.NextCursor
			}
		}
		if assetPage.NextCursor == "" {
			break
		}
		assetCursor = assetPage.NextCursor
	}
	return previous, previousParams, nil
}

// EndpointChangeType names how an endpoint differs from the target's
// previous discovery run (phase7.md §44). method_added/method_removed
// are deliberately not separate types here: this model's endpoint
// identity already includes Method (phase7.md §7), so a new method
// appearing for an already-known path surfaces as an ordinary "added"
// entry at that (method, url) identity — correct and unambiguous without
// needing a second, path-grouped comparison pass.
type EndpointChangeType string

// Recognized endpoint change types.
const (
	EndpointChangeAdded                 EndpointChangeType = "added"
	EndpointChangeRemoved               EndpointChangeType = "removed"
	EndpointChangeParameterAdded        EndpointChangeType = "parameter_added"
	EndpointChangeParameterRemoved      EndpointChangeType = "parameter_removed"
	EndpointChangeClassificationChanged EndpointChangeType = "classification_changed"
	EndpointChangeAPIVersionChanged     EndpointChangeType = "api_version_changed"
	EndpointChangeStatusChanged         EndpointChangeType = "status_changed"
)

// EndpointChange is one detected difference between two discovery runs
// against the same target (phase7.md §44). A status-code change is
// always reported as status_changed, never as removed+added — the
// endpoint still exists (phase7.md §45).
type EndpointChange struct {
	AssetID                uuid.UUID
	Method                 string
	URL                    string
	Type                   EndpointChangeType
	PreviousStatusCode     *int
	CurrentStatusCode      *int
	PreviousAPIVersion     string
	CurrentAPIVersion      string
	PreviousClassification string
	CurrentClassification  string
	Parameter              string // set only for parameter_added/parameter_removed
	DetectedAt             time.Time
}

// detectEndpointChanges compares previous (this target's endpoint state
// before the run) to current (what this run persisted), per phase7.md
// §44/§45. Minor/no-op differences (identical status, identical
// parameters, ...) produce no Change. A removed endpoint's parameters
// are not individually reported as parameter_removed — the single
// "removed" Change already covers it; parameter-level changes are only
// meaningful for an endpoint that still exists in both snapshots.
func detectEndpointChanges(previous, current map[string]domainendpoint.Endpoint, previousParams, currentParams map[string]map[string]bool) []EndpointChange {
	now := time.Now().UTC()
	var changes []EndpointChange

	for key, prev := range previous {
		if _, stillFound := current[key]; !stillFound {
			changes = append(changes, EndpointChange{
				AssetID: prev.AssetID, Method: string(prev.Method), URL: prev.URL,
				Type: EndpointChangeRemoved, PreviousStatusCode: prev.StatusCode, DetectedAt: now,
			})
		}
	}

	for key, curr := range current {
		prev, existed := previous[key]
		if !existed {
			changes = append(changes, EndpointChange{
				AssetID: curr.AssetID, Method: string(curr.Method), URL: curr.URL,
				Type: EndpointChangeAdded, CurrentStatusCode: curr.StatusCode, DetectedAt: now,
			})
			continue
		}

		if !statusCodeEqual(prev.StatusCode, curr.StatusCode) {
			changes = append(changes, EndpointChange{
				AssetID: curr.AssetID, Method: string(curr.Method), URL: curr.URL,
				Type: EndpointChangeStatusChanged, PreviousStatusCode: prev.StatusCode, CurrentStatusCode: curr.StatusCode,
				DetectedAt: now,
			})
		}
		if curr.APIVersion != "" && curr.APIVersion != prev.APIVersion {
			changes = append(changes, EndpointChange{
				AssetID: curr.AssetID, Method: string(curr.Method), URL: curr.URL,
				Type: EndpointChangeAPIVersionChanged, PreviousAPIVersion: prev.APIVersion, CurrentAPIVersion: curr.APIVersion,
				DetectedAt: now,
			})
		}
		if curr.Classification != "" && curr.Classification != prev.Classification {
			changes = append(changes, EndpointChange{
				AssetID: curr.AssetID, Method: string(curr.Method), URL: curr.URL,
				Type:                   EndpointChangeClassificationChanged,
				PreviousClassification: string(prev.Classification), CurrentClassification: string(curr.Classification),
				DetectedAt: now,
			})
		}

		prevParams, currParams := previousParams[key], currentParams[key]
		for name := range currParams {
			if !prevParams[name] {
				changes = append(changes, EndpointChange{
					AssetID: curr.AssetID, Method: string(curr.Method), URL: curr.URL,
					Type: EndpointChangeParameterAdded, Parameter: name, DetectedAt: now,
				})
			}
		}
		for name := range prevParams {
			if !currParams[name] {
				changes = append(changes, EndpointChange{
					AssetID: curr.AssetID, Method: string(curr.Method), URL: curr.URL,
					Type: EndpointChangeParameterRemoved, Parameter: name, DetectedAt: now,
				})
			}
		}
	}

	return changes
}

func statusCodeEqual(a, b *int) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}
