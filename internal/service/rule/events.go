package rule

import (
	"context"
	"time"

	"github.com/google/uuid"

	domainasset "ai-recon-platform/internal/domain/asset"
	assetrepo "ai-recon-platform/internal/repository/asset"
	endpointrepo "ai-recon-platform/internal/repository/endpoint"
	findingrepo "ai-recon-platform/internal/repository/finding"
	fingerprintrepo "ai-recon-platform/internal/repository/fingerprint"
	intelrepo "ai-recon-platform/internal/repository/intelligence"
	"ai-recon-platform/internal/repository/pagination"
	"ai-recon-platform/internal/ruleengine"
)

// buildEvents assembles every normalized Event within [from, to) for
// targetID — this is the one place this platform's already-persisted
// findings/assets/fingerprints/intelligence-records/endpoints become
// internal/ruleengine.Event values (see internal/ruleengine's package
// doc comment for why there is no separate event-log table). Callers
// must have already checked the requested range against
// Config.EffectiveHistoricalMaxRange (phase11.md §58/§108) — this method
// does not re-check it, so it can also be used for a single-evaluation-
// cycle's narrow window during normal (non-historical) operation.
func (s *Service) buildEvents(ctx context.Context, targetID uuid.UUID, from, to time.Time) ([]ruleengine.Event, error) {
	var events []ruleengine.Event

	findingEvents, err := s.findingEvents(ctx, targetID, from, to)
	if err != nil {
		return nil, err
	}
	events = append(events, findingEvents...)

	assetEvents, assets, err := s.assetEvents(ctx, targetID, from, to)
	if err != nil {
		return nil, err
	}
	events = append(events, assetEvents...)

	fpEvents, err := s.fingerprintEvents(ctx, targetID, from, to)
	if err != nil {
		return nil, err
	}
	events = append(events, fpEvents...)

	intelEvents, err := s.intelligenceEvents(ctx, targetID, from, to)
	if err != nil {
		return nil, err
	}
	events = append(events, intelEvents...)

	// Endpoint observations are queried per-asset (internal/repository/
	// endpoint has no direct target_id filter — phase11.md §60's index
	// wishlist doesn't currently extend that far); bounded by the same
	// asset list already fetched for assetEvents above, not a second
	// full target scan.
	endpointEvents, err := s.endpointEvents(ctx, assets, from, to)
	if err != nil {
		return nil, err
	}
	events = append(events, endpointEvents...)

	return events, nil
}

func inWindow(t, from, to time.Time) bool {
	return !t.Before(from) && t.Before(to)
}

func (s *Service) findingEvents(ctx context.Context, targetID uuid.UUID, from, to time.Time) ([]ruleengine.Event, error) {
	var out []ruleengine.Event
	cursor := ""
	for {
		page, err := s.findings.List(ctx, findingrepo.ListFilter{TargetID: targetID, Pagination: pagination.Params{Limit: pagination.MaxLimit, Cursor: cursor}})
		if err != nil {
			return nil, err
		}
		for _, f := range page.Items {
			if !inWindow(f.LastSeen, from, to) {
				continue
			}
			out = append(out, ruleengine.Event{
				Type: ruleengine.EventFinding, SourceID: f.ID, TargetID: f.TargetID, AssetID: f.AssetID, Timestamp: f.LastSeen,
				Fields: map[string]any{
					"event.timestamp": f.LastSeen, "event.target_id": f.TargetID.String(), "event.asset_id": f.AssetID.String(),
					"finding.severity": string(f.Severity), "finding.confidence": float64(f.Confidence),
					"finding.category": string(f.Category), "finding.status": string(f.Status),
					"finding.detector_id": f.DetectorID, "finding.scope": string(f.Scope),
				},
			})
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	return out, nil
}

func (s *Service) assetEvents(ctx context.Context, targetID uuid.UUID, from, to time.Time) ([]ruleengine.Event, []domainasset.Asset, error) {
	var out []ruleengine.Event
	var assets []domainasset.Asset
	cursor := ""
	for {
		page, err := s.assets.List(ctx, assetrepo.ListFilter{TargetID: targetID, Pagination: pagination.Params{Limit: pagination.MaxLimit, Cursor: cursor}})
		if err != nil {
			return nil, nil, err
		}
		for _, a := range page.Items {
			assets = append(assets, a)
			if !inWindow(a.LastSeen, from, to) {
				continue
			}
			out = append(out, ruleengine.Event{
				Type: ruleengine.EventAssetObservation, SourceID: a.ID, TargetID: a.TargetID, AssetID: a.ID, Timestamp: a.LastSeen,
				Fields: map[string]any{
					"event.timestamp": a.LastSeen, "event.target_id": a.TargetID.String(), "event.asset_id": a.ID.String(),
					"asset.type": string(a.Type), "asset.status": string(a.Status), "asset.confidence": float64(a.Confidence),
					"asset.hostname": domainasset.StringField(a.Hostname), "asset.ip": domainasset.StringField(a.IP), "asset.source": a.Source,
				},
			})
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	return out, assets, nil
}

func (s *Service) fingerprintEvents(ctx context.Context, targetID uuid.UUID, from, to time.Time) ([]ruleengine.Event, error) {
	var out []ruleengine.Event
	cursor := ""
	for {
		page, err := s.fingerprints.List(ctx, fingerprintrepo.ListFilter{TargetID: targetID, Pagination: pagination.Params{Limit: pagination.MaxLimit, Cursor: cursor}})
		if err != nil {
			return nil, err
		}
		for _, fp := range page.Items {
			if !inWindow(fp.LastSeen, from, to) {
				continue
			}
			out = append(out, ruleengine.Event{
				Type: ruleengine.EventFingerprintChange, SourceID: fp.ID, TargetID: fp.TargetID, AssetID: fp.AssetID, Timestamp: fp.LastSeen,
				Fields: map[string]any{
					"event.timestamp": fp.LastSeen, "event.target_id": fp.TargetID.String(), "event.asset_id": fp.AssetID.String(),
					"fingerprint.technology": fp.Technology, "fingerprint.category": string(fp.Category),
					"fingerprint.confidence": float64(fp.Confidence), "fingerprint.status": string(fp.Status),
				},
			})
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	return out, nil
}

func (s *Service) intelligenceEvents(ctx context.Context, targetID uuid.UUID, from, to time.Time) ([]ruleengine.Event, error) {
	var out []ruleengine.Event
	cursor := ""
	for {
		page, err := s.intelligence.ListRecords(ctx, intelrepo.RecordListFilter{TargetID: targetID, Pagination: pagination.Params{Limit: pagination.MaxLimit, Cursor: cursor}})
		if err != nil {
			return nil, err
		}
		for _, rec := range page.Items {
			if !inWindow(rec.RetrievedAt, from, to) {
				continue
			}
			out = append(out, ruleengine.Event{
				Type: ruleengine.EventIntelligenceRecord, SourceID: rec.ID, TargetID: rec.TargetID, Timestamp: rec.RetrievedAt,
				Fields: map[string]any{
					"event.timestamp": rec.RetrievedAt, "event.target_id": rec.TargetID.String(), "event.asset_id": "",
					"intelligence.verdict": string(rec.Verdict), "intelligence.confidence": string(rec.Confidence),
					"intelligence.category": string(rec.Category), "intelligence.source_type": rec.SourceType,
					"intelligence.indicator_type": string(rec.IndicatorType),
				},
			})
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	return out, nil
}

func (s *Service) endpointEvents(ctx context.Context, assets []domainasset.Asset, from, to time.Time) ([]ruleengine.Event, error) {
	var out []ruleengine.Event
	for _, a := range assets {
		cursor := ""
		for {
			page, err := s.endpoints.ListByAsset(ctx, endpointrepo.ListFilter{AssetID: a.ID, Pagination: pagination.Params{Limit: pagination.MaxLimit, Cursor: cursor}})
			if err != nil {
				return nil, err
			}
			for _, ep := range page.Items {
				if !inWindow(ep.LastSeen, from, to) {
					continue
				}
				out = append(out, ruleengine.Event{
					Type: ruleengine.EventEndpointObservation, SourceID: ep.ID, TargetID: a.TargetID, AssetID: a.ID, Timestamp: ep.LastSeen,
					Fields: map[string]any{
						"event.timestamp": ep.LastSeen, "event.target_id": a.TargetID.String(), "event.asset_id": a.ID.String(),
						"endpoint.classification": string(ep.Classification), "endpoint.confidence": ep.Confidence,
						"endpoint.method": string(ep.Method), "endpoint.status": string(ep.Status),
					},
				})
			}
			if page.NextCursor == "" {
				break
			}
			cursor = page.NextCursor
		}
	}
	return out, nil
}
