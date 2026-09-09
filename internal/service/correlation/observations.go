package correlation

import (
	"context"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/correlation"
	domainasset "ai-surface-platform/internal/domain/asset"
	domainrule "ai-surface-platform/internal/domain/rule"
	assetrepo "ai-surface-platform/internal/repository/asset"
	endpointrepo "ai-surface-platform/internal/repository/endpoint"
	findingrepo "ai-surface-platform/internal/repository/finding"
	fingerprintrepo "ai-surface-platform/internal/repository/fingerprint"
	intelrepo "ai-surface-platform/internal/repository/intelligence"
	"ai-surface-platform/internal/repository/pagination"
	rulerepo "ai-surface-platform/internal/repository/rule"
)

func inWindow(t, from, to time.Time) bool { return !t.Before(from) && t.Before(to) }

// assetIndex maps an already-persisted row's own ID (a finding, endpoint,
// or fingerprint ID) to the asset it belongs to — built once per
// buildObservations call so resolving a DetectionMatch's evidence back to
// "which asset does this actually touch" (phase11.md's DetectionMatch
// carries no AssetID of its own) never requires a second query per match.
type assetIndex map[uuid.UUID]uuid.UUID

// buildObservations assembles every internal/correlation.Observation
// within [from, to) for targetID — this platform's already-persisted
// assets/endpoints/findings/intelligence-records/detection-matches/
// alerts, exactly as internal/service/rule.buildEvents does for Phase
// 11's own normalized events (see that method's doc comment for why
// there is no separate raw-event table). Bounded by
// Config.EffectiveMaxCandidates via the caller (see evaluate.go) — this
// method itself does not truncate, so callers must not pass an
// unbounded [from, to) range without their own limit.
func (s *Service) buildObservations(ctx context.Context, targetID uuid.UUID, from, to time.Time) ([]correlation.Observation, error) {
	var out []correlation.Observation
	idx := assetIndex{}

	findingObs, findingAssetOf, err := s.findingObservations(ctx, targetID, from, to)
	if err != nil {
		return nil, err
	}
	out = append(out, findingObs...)
	for id, assetID := range findingAssetOf {
		idx[id] = assetID
	}

	assetObs, assets, err := s.assetObservations(ctx, targetID, from, to)
	if err != nil {
		return nil, err
	}
	out = append(out, assetObs...)

	endpointObs, endpointAssetOf, err := s.endpointObservations(ctx, assets, from, to)
	if err != nil {
		return nil, err
	}
	out = append(out, endpointObs...)
	for id, assetID := range endpointAssetOf {
		idx[id] = assetID
	}

	fingerprintAssetOf, err := s.fingerprintAssetIndex(ctx, targetID)
	if err != nil {
		return nil, err
	}
	for id, assetID := range fingerprintAssetOf {
		idx[id] = assetID
	}

	intelObs, err := s.intelligenceObservations(ctx, targetID, from, to)
	if err != nil {
		return nil, err
	}
	out = append(out, intelObs...)

	ruleCategoryCache := map[uuid.UUID]string{}
	matchObs, matchAssetOf, err := s.detectionMatchObservations(ctx, targetID, from, to, idx, ruleCategoryCache)
	if err != nil {
		return nil, err
	}
	out = append(out, matchObs...)

	alertObs, err := s.alertObservations(ctx, targetID, from, to, matchAssetOf)
	if err != nil {
		return nil, err
	}
	out = append(out, alertObs...)

	return out, nil
}

func (s *Service) findingObservations(ctx context.Context, targetID uuid.UUID, from, to time.Time) ([]correlation.Observation, map[uuid.UUID]uuid.UUID, error) {
	var out []correlation.Observation
	assetOf := map[uuid.UUID]uuid.UUID{}
	cursor := ""
	for {
		page, err := s.findings.List(ctx, findingrepo.ListFilter{TargetID: targetID, Pagination: pagination.Params{Limit: pagination.MaxLimit, Cursor: cursor}})
		if err != nil {
			return nil, nil, err
		}
		for _, f := range page.Items {
			assetOf[f.ID] = f.AssetID
			if !inWindow(f.LastSeen, from, to) {
				continue
			}
			out = append(out, correlation.Observation{
				Type: correlation.NodeFinding, ReferenceID: f.ID, TargetID: f.TargetID, AssetID: f.AssetID, Timestamp: f.LastSeen,
				Severity: string(f.Severity), Category: string(f.Category),
			})
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	return out, assetOf, nil
}

func (s *Service) assetObservations(ctx context.Context, targetID uuid.UUID, from, to time.Time) ([]correlation.Observation, []domainasset.Asset, error) {
	var out []correlation.Observation
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
			out = append(out, correlation.Observation{
				Type: correlation.NodeAsset, ReferenceID: a.ID, TargetID: a.TargetID, AssetID: a.ID, Timestamp: a.LastSeen,
				IP: domainasset.StringField(a.IP), Hostname: domainasset.StringField(a.Hostname),
			})
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	return out, assets, nil
}

func (s *Service) endpointObservations(ctx context.Context, assets []domainasset.Asset, from, to time.Time) ([]correlation.Observation, map[uuid.UUID]uuid.UUID, error) {
	var out []correlation.Observation
	assetOf := map[uuid.UUID]uuid.UUID{}
	for _, a := range assets {
		cursor := ""
		for {
			page, err := s.endpoints.ListByAsset(ctx, endpointrepo.ListFilter{AssetID: a.ID, Pagination: pagination.Params{Limit: pagination.MaxLimit, Cursor: cursor}})
			if err != nil {
				return nil, nil, err
			}
			for _, ep := range page.Items {
				assetOf[ep.ID] = a.ID
				if !inWindow(ep.LastSeen, from, to) {
					continue
				}
				out = append(out, correlation.Observation{
					Type: correlation.NodeEndpoint, ReferenceID: ep.ID, TargetID: a.TargetID, AssetID: a.ID, Timestamp: ep.LastSeen,
					IP: domainasset.StringField(a.IP), Hostname: domainasset.StringField(a.Hostname),
				})
			}
			if page.NextCursor == "" {
				break
			}
			cursor = page.NextCursor
		}
	}
	return out, assetOf, nil
}

// fingerprintAssetIndex resolves fingerprint IDs to their asset, for
// DetectionMatch evidence-tracing only (see detectionMatchObservations) —
// this platform does not correlate technology fingerprints as a Phase 12
// node type of their own (Phase 9's own correlation package already
// covers technology-level correlation — phase12.md's "do not create
// duplicate... systems").
func (s *Service) fingerprintAssetIndex(ctx context.Context, targetID uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	assetOf := map[uuid.UUID]uuid.UUID{}
	cursor := ""
	for {
		page, err := s.fingerprints.List(ctx, fingerprintrepo.ListFilter{TargetID: targetID, Pagination: pagination.Params{Limit: pagination.MaxLimit, Cursor: cursor}})
		if err != nil {
			return nil, err
		}
		for _, fp := range page.Items {
			assetOf[fp.ID] = fp.AssetID
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	return assetOf, nil
}

func (s *Service) intelligenceObservations(ctx context.Context, targetID uuid.UUID, from, to time.Time) ([]correlation.Observation, error) {
	var out []correlation.Observation
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
			out = append(out, correlation.Observation{
				Type: correlation.NodeIntelligenceRecord, ReferenceID: rec.ID, TargetID: rec.TargetID, Timestamp: rec.RetrievedAt,
				IndicatorType: string(rec.IndicatorType), IndicatorValue: rec.IndicatorValue,
				Verdict: string(rec.Verdict), Confidence: string(rec.Confidence),
				Attributes: map[string]any{"provider_id": rec.ProviderID},
			})
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	return out, nil
}

// ruleCategory returns ruleID's Category, caching lookups across one
// buildObservations call so N detection matches referencing the same
// rule never issue N separate queries.
func (s *Service) ruleCategory(ctx context.Context, ruleID uuid.UUID, cache map[uuid.UUID]string) string {
	if category, ok := cache[ruleID]; ok {
		return category
	}
	r, err := s.rules.GetRuleByID(ctx, ruleID)
	category := ""
	if err == nil {
		category = r.Category
	}
	cache[ruleID] = category
	return category
}

// resolveMatchAsset returns the asset a DetectionMatch relates to, found
// via its own evidence (phase12.md §18): the match row itself carries no
// AssetID, so its first evidence reference resolvable through idx wins.
// This is a documented heuristic — a match with evidence spanning
// multiple assets (uncommon, since most rules group by asset) reports
// only the first one found.
func (s *Service) resolveMatchAsset(ctx context.Context, matchID uuid.UUID, idx assetIndex) uuid.UUID {
	rows, err := s.evidence.ListByMatch(ctx, matchID)
	if err != nil {
		return uuid.Nil
	}
	for _, ev := range rows {
		if ev.SourceType == domainrule.SourceAssetObservation {
			return ev.SourceID
		}
		if assetID, ok := idx[ev.SourceID]; ok {
			return assetID
		}
	}
	return uuid.Nil
}

func (s *Service) detectionMatchObservations(ctx context.Context, targetID uuid.UUID, from, to time.Time, idx assetIndex, ruleCategoryCache map[uuid.UUID]string) ([]correlation.Observation, map[uuid.UUID]uuid.UUID, error) {
	var out []correlation.Observation
	assetOf := map[uuid.UUID]uuid.UUID{}
	cursor := ""
	for {
		page, err := s.matches.ListMatches(ctx, rulerepo.MatchListFilter{TargetID: targetID, Pagination: pagination.Params{Limit: pagination.MaxLimit, Cursor: cursor}})
		if err != nil {
			return nil, nil, err
		}
		for _, m := range page.Items {
			if !inWindow(m.LastObservedAt, from, to) {
				continue
			}
			assetID := s.resolveMatchAsset(ctx, m.ID, idx)
			assetOf[m.ID] = assetID
			out = append(out, correlation.Observation{
				Type: correlation.NodeDetectionMatch, ReferenceID: m.ID, TargetID: m.TargetID, AssetID: assetID, Timestamp: m.LastObservedAt,
				Severity: string(m.Severity), RuleID: m.RuleID, RuleCategory: s.ruleCategory(ctx, m.RuleID, ruleCategoryCache),
			})
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	return out, assetOf, nil
}

func (s *Service) alertObservations(ctx context.Context, targetID uuid.UUID, from, to time.Time, matchAssetOf map[uuid.UUID]uuid.UUID) ([]correlation.Observation, error) {
	var out []correlation.Observation
	cursor := ""
	for {
		page, err := s.alerts.ListAlerts(ctx, rulerepo.AlertListFilter{TargetID: targetID, Pagination: pagination.Params{Limit: pagination.MaxLimit, Cursor: cursor}})
		if err != nil {
			return nil, err
		}
		for _, a := range page.Items {
			if !inWindow(a.LastObservedAt, from, to) {
				continue
			}
			out = append(out, correlation.Observation{
				Type: correlation.NodeAlert, ReferenceID: a.ID, TargetID: a.TargetID, AssetID: matchAssetOf[a.DetectionMatchID], Timestamp: a.LastObservedAt,
				Severity: string(a.Severity),
			})
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	return out, nil
}
