package intelligence

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	domainasset "ai-surface-platform/internal/domain/asset"
	domaincorrelation "ai-surface-platform/internal/domain/correlation"
	domainendpoint "ai-surface-platform/internal/domain/endpoint"
	domainfinding "ai-surface-platform/internal/domain/finding"
	domainintel "ai-surface-platform/internal/domain/intelligence"
	domaininvestigation "ai-surface-platform/internal/domain/investigation"
	domainrule "ai-surface-platform/internal/domain/rule"
	apperrors "ai-surface-platform/internal/errors"
	"ai-surface-platform/internal/intelligence"
	"ai-surface-platform/internal/intelligence/providers"
	"ai-surface-platform/internal/intelligence/risk"
	correlationrepo "ai-surface-platform/internal/repository/correlation"
	endpointrepo "ai-surface-platform/internal/repository/endpoint"
	findingrepo "ai-surface-platform/internal/repository/finding"
	intelrepo "ai-surface-platform/internal/repository/intelligence"
	investigationrepo "ai-surface-platform/internal/repository/investigation"
	"ai-surface-platform/internal/repository/pagination"
	rulerepo "ai-surface-platform/internal/repository/rule"
)

// intelrepoVulnFilter builds the catalog listing filter for one observed
// product name.
func intelrepoVulnFilter(product string) intelrepo.VulnerabilityListFilter {
	return intelrepo.VulnerabilityListFilter{AffectedProduct: product, Pagination: pagination.Params{Limit: pagination.MaxLimit}}
}

// apiClassifications/sensitiveClassifications name the Phase 7 endpoint
// classifications this package treats as "an API surface is exposed" /
// "a sensitive endpoint" for risk exposure scoring (phase10.md §37) —
// deliberately small, documented sets, not "every classification".
var apiClassifications = map[domainendpoint.Classification]bool{
	"api": true, "graphql": true, "openapi": true, "swagger": true,
}
var sensitiveClassifications = map[domainendpoint.Classification]bool{
	"auth": true, "api": true,
}

// internetFacingAssetTypes are asset types this package treats as
// internet-facing for risk exposure scoring (phase10.md §37) — an
// HTTP(S)/API/AI endpoint, or any asset carrying a URL.
var internetFacingAssetTypes = map[domainasset.Type]bool{
	domainasset.TypeHTTPEndpoint: true, domainasset.TypeAPIEndpoint: true, domainasset.TypeAIEndpoint: true,
}

// AssetEnrichment is EnrichAsset's full result.
type AssetEnrichment struct {
	Asset                domainasset.Asset
	IntelligenceLookups  []LookupReport
	VulnerabilityMatches []domainintel.VulnerabilityMatch
	Risk                 domainintel.RiskScore
}

// EnrichAsset enriches one asset end-to-end: intelligence lookups for
// every indicator it carries, vulnerability matching against its Phase 6
// technology fingerprints, and a fresh risk score (phase10.md §38).
// Findings/investigations this asset relates to are never modified —
// enrichment is always attached separately (phase10.md §38).
func (s *Service) EnrichAsset(ctx context.Context, assetID uuid.UUID) (AssetEnrichment, error) {
	asset, err := s.assets.GetByID(ctx, assetID)
	if err != nil {
		return AssetEnrichment{}, err
	}

	dataset := s.buildLocalDataset(ctx, asset)

	var lookups []LookupReport
	var overallIntel intelligence.AggregatedResult
	for _, indicator := range indicatorsForAsset(asset) {
		report, lookupErr := s.enrichWithDataset(ctx, asset.TargetID, indicator, dataset)
		if lookupErr != nil {
			s.logger.Error("intelligence_asset_enrich_lookup_failed", "asset_id", assetID, "indicator", indicator.Key(), "error", lookupErr)
			continue
		}
		lookups = append(lookups, report)
		if report.Aggregated.Verdict.Rank() > overallIntel.Verdict.Rank() {
			overallIntel = report.Aggregated
		}
	}

	host := hostKeyForAsset(asset)
	matches, err := s.matchAssetVulnerabilities(ctx, asset, dataset.Technologies[host])
	if err != nil {
		s.logger.Error("intelligence_vulnerability_match_failed", "asset_id", assetID, "error", err)
	}

	riskInput := s.buildAssetRiskInput(ctx, asset, matches, overallIntel)
	riskResult := s.scorer.Calculate(riskInput)
	riskScore, err := s.persistRiskScore(ctx, asset.TargetID, domainintel.EntityAsset, assetID, riskResult)
	if err != nil {
		return AssetEnrichment{}, err
	}

	return AssetEnrichment{Asset: asset, IntelligenceLookups: lookups, VulnerabilityMatches: matches, Risk: riskScore}, nil
}

// matchAssetVulnerabilities evaluates every technology observation
// against the catalog entries sharing its product, persisting each
// resulting match (phase10.md §14/§16) — never a match based on product
// name alone (phase10.md §15). It records a
// EventVulnerabilityMatchCreated event for every newly-created confirmed
// or probable match (phase10.md §50).
func (s *Service) matchAssetVulnerabilities(ctx context.Context, asset domainasset.Asset, techs []providers.TechnologyObservation) ([]domainintel.VulnerabilityMatch, error) {
	var out []domainintel.VulnerabilityMatch
	for _, tech := range techs {
		if tech.Product == "" {
			continue
		}
		catalogPage, err := s.vulns.ListVulnerabilityRecords(ctx, intelrepoVulnFilter(tech.Product))
		if err != nil {
			return out, fmt.Errorf("loading catalog for %s: %w", tech.Product, err)
		}
		if len(catalogPage.Items) == 0 {
			continue
		}

		entries := make([]intelligence.CatalogEntry, 0, len(catalogPage.Items))
		byID := map[string]domainintel.VulnerabilityRecord{}
		for _, v := range catalogPage.Items {
			entries = append(entries, intelligence.CatalogEntry{
				ID: v.ID.String(), Identifier: v.Identifier, Title: v.Title,
				Severity: intelligence.Severity(v.Severity), AffectedProduct: v.AffectedProduct, VersionConstraints: v.VersionConstraints,
			})
			byID[v.ID.String()] = v
		}

		matcher := intelligence.NewMatcher(entries)
		for _, m := range matcher.Evaluate(intelligence.TechnologyObservation{Product: tech.Product, Vendor: tech.Vendor, Version: tech.Version}) {
			vulnID, parseErr := uuid.Parse(m.CatalogEntryID)
			if parseErr != nil {
				continue
			}
			domainMatch := domainintel.VulnerabilityMatch{
				TargetID: asset.TargetID, AssetID: asset.ID, VulnerabilityID: vulnID,
				AffectedComponent: m.AffectedComponent, ObservedProduct: m.ObservedProduct, ObservedVersion: m.ObservedVersion,
				MatchStatus: domainintel.MatchStatus(m.MatchStatus), Confidence: domainintel.Confidence(m.Confidence),
				Evidence: m.Evidence, MatchingRule: m.MatchingRule,
			}
			saved, created, upsertErr := s.vulns.UpsertVulnerabilityMatch(ctx, domainMatch)
			if upsertErr != nil {
				s.logger.Error("intelligence_vulnerability_match_persist_failed", "asset_id", asset.ID, "vulnerability_id", vulnID, "error", upsertErr)
				continue
			}
			out = append(out, saved)
			if created && (saved.MatchStatus == domainintel.MatchConfirmed || saved.MatchStatus == domainintel.MatchProbable) {
				s.recordMatchEvent(ctx, asset.TargetID, byID[m.CatalogEntryID], saved)
			}
		}
	}
	return out, nil
}

func (s *Service) recordMatchEvent(ctx context.Context, targetID uuid.UUID, vuln domainintel.VulnerabilityRecord, match domainintel.VulnerabilityMatch) {
	_, err := s.events.RecordEvent(ctx, domainintel.EnrichmentEvent{
		TargetID: targetID, EventType: domainintel.EventVulnerabilityMatchCreated,
		Source: "vulnerability_matcher", SourceID: match.ID.String(), Timestamp: time.Now().UTC(),
		NewValue: string(match.MatchStatus), Confidence: match.Confidence,
	})
	if err != nil {
		s.logger.Error("intelligence_event_record_failed", "vulnerability", vuln.Identifier, "error", err)
	}
}

// buildAssetRiskInput assembles a risk.Input for asset from
// already-persisted exposure/vulnerability/intelligence/criticality
// signals (phase10.md §34/§37).
func (s *Service) buildAssetRiskInput(ctx context.Context, asset domainasset.Asset, matches []domainintel.VulnerabilityMatch, overallIntel intelligence.AggregatedResult) risk.Input {
	input := risk.Input{}

	// Phase 11 extension (phase11.md §98) — optional: only queried when
	// a caller has wired a detection-match repository via
	// WithDetectionMatches. Detection matches are scoped by target, not
	// individually by asset (a threshold/sequence match may span several
	// assets), so this counts open matches for the ASSET'S TARGET as a
	// whole — every asset within one target currently sees the same
	// count. See docs/architecture/detection-engine.md's Known
	// Limitations for the honest granularity tradeoff.
	if s.detectionMatches != nil {
		matchPage, err := s.detectionMatches.ListMatches(ctx, rulerepo.MatchListFilter{
			TargetID: asset.TargetID, Status: domainrule.MatchOpen, Pagination: pagination.Params{Limit: pagination.MaxLimit},
		})
		if err != nil {
			s.logger.Error("intelligence_risk_detection_match_list_failed", "asset_id", asset.ID, "error", err)
		} else {
			input.OpenDetectionMatchCount = len(matchPage.Items)
		}
	}

	// Phase 12 extension (phase12.md §34) — optional: only queried when a
	// caller has wired a correlation repository via WithCorrelations.
	// Correlations are target-scoped, not individually joined to an
	// asset, the same honest granularity tradeoff documented above for
	// detection matches.
	if s.correlations != nil {
		corrPage, err := s.correlations.ListCorrelations(ctx, correlationrepo.ListFilter{
			TargetID: asset.TargetID, Status: domaincorrelation.StatusOpen, Pagination: pagination.Params{Limit: pagination.MaxLimit},
		})
		if err != nil {
			s.logger.Error("intelligence_risk_correlation_list_failed", "asset_id", asset.ID, "error", err)
		} else {
			input.OpenCorrelationCount = len(corrPage.Items)
		}
	}

	openPage, err := s.findings.List(ctx, findingrepo.ListFilter{AssetID: asset.ID, Pagination: pagination.Params{Limit: pagination.MaxLimit}})
	if err != nil {
		s.logger.Error("intelligence_risk_finding_list_failed", "asset_id", asset.ID, "error", err)
	} else {
		var best domainfinding.Finding
		for _, f := range openPage.Items {
			if f.Status.Open() && f.Severity.Rank() >= best.Severity.Rank() {
				best = f
			}
		}
		input.HighestFindingSeverity = risk.Severity(best.Severity)
		input.HighestFindingConfidenceHigh = best.Confidence.Level() == domainfinding.LevelHigh || best.Confidence.Level() == domainfinding.LevelVeryHigh
	}

	input.InternetFacing = internetFacingAssetTypes[asset.Type] || (asset.URL != nil && *asset.URL != "")

	endpointPage, err := s.endpoints.ListByAsset(ctx, endpointrepo.ListFilter{AssetID: asset.ID, Pagination: pagination.Params{Limit: pagination.MaxLimit}})
	if err != nil {
		s.logger.Error("intelligence_risk_endpoint_list_failed", "asset_id", asset.ID, "error", err)
	} else {
		for _, ep := range endpointPage.Items {
			if apiClassifications[ep.Classification] {
				input.ExposedAPI = true
			}
			if sensitiveClassifications[ep.Classification] {
				input.SensitiveEndpointCount++
			}
		}
	}

	for _, m := range matches {
		switch m.MatchStatus {
		case domainintel.MatchConfirmed:
			input.HighestVulnerabilityStatus = risk.VulnerabilityConfirmed
		case domainintel.MatchProbable:
			if input.HighestVulnerabilityStatus != risk.VulnerabilityConfirmed {
				input.HighestVulnerabilityStatus = risk.VulnerabilityProbable
			}
		}
	}

	input.IntelligenceVerdict = risk.IntelligenceVerdict(overallIntel.Verdict)

	crit, found, err := s.crit.GetCriticality(ctx, asset.ID)
	if err != nil {
		s.logger.Error("intelligence_risk_criticality_lookup_failed", "asset_id", asset.ID, "error", err)
	}
	if found {
		input.AssetCriticality = risk.Criticality(crit.Criticality)
	} else {
		input.AssetCriticality = risk.CriticalityNormal
	}

	input.RecentChange = time.Since(asset.UpdatedAt) < 7*24*time.Hour

	return input
}

// persistRiskScore maps a risk.Result onto a domainintel.RiskScore,
// creates it (always a new row — phase10.md §45/§46), and emits an
// EventRiskScoreIncreased event when the score rose versus the previous
// one (phase10.md §49).
func (s *Service) persistRiskScore(ctx context.Context, targetID uuid.UUID, entityType domainintel.EntityType, entityID uuid.UUID, result risk.Result) (domainintel.RiskScore, error) {
	previous, prevErr := s.risks.GetLatestRiskScore(ctx, entityType, entityID)

	factors := make([]domainintel.RiskFactor, 0, len(result.Factors))
	for _, f := range result.Factors {
		factors = append(factors, domainintel.RiskFactor{Name: f.Name, Points: f.Points, Description: f.Description})
	}

	score := domainintel.RiskScore{
		TargetID: targetID, EntityType: entityType, EntityID: entityID,
		Score: result.Score, Severity: domainintel.Severity(result.Severity), Confidence: domainintel.Confidence(result.Confidence),
		ModelVersion: result.ModelVersion, Factors: factors, Explanation: result.Explanation, CalculatedAt: time.Now().UTC(),
	}
	saved, err := s.risks.CreateRiskScore(ctx, score)
	if err != nil {
		return domainintel.RiskScore{}, err
	}

	if prevErr == nil && saved.Score > previous.Score {
		_, err := s.events.RecordEvent(ctx, domainintel.EnrichmentEvent{
			TargetID: targetID, EventType: domainintel.EventRiskScoreIncreased,
			Source: "risk_engine", SourceID: entityID.String(), Timestamp: time.Now().UTC(),
			PreviousValue: fmt.Sprintf("%d", previous.Score), NewValue: fmt.Sprintf("%d", saved.Score),
		})
		if err != nil {
			s.logger.Error("intelligence_event_record_failed", "entity_id", entityID, "error", err)
		}
	}

	return saved, nil
}

// FindingEnrichment is EnrichFinding's result.
type FindingEnrichment struct {
	Finding domainfinding.Finding
	Asset   AssetEnrichment
	Risk    domainintel.RiskScore
}

// EnrichFinding enriches the finding's own risk context by enriching its
// underlying asset, then layering the finding's own severity/confidence
// on top (phase10.md §38's worked example: a finding's risk reflects its
// technology, vulnerability matches, and intelligence together).
func (s *Service) EnrichFinding(ctx context.Context, findingID uuid.UUID) (FindingEnrichment, error) {
	f, err := s.findings.GetByID(ctx, findingID)
	if err != nil {
		return FindingEnrichment{}, err
	}

	assetEnrichment, err := s.EnrichAsset(ctx, f.AssetID)
	if err != nil {
		return FindingEnrichment{}, err
	}

	input := s.buildAssetRiskInput(ctx, assetEnrichment.Asset, assetEnrichment.VulnerabilityMatches, bestIntel(assetEnrichment.IntelligenceLookups))
	// The finding under enrichment always sets the finding-severity
	// factor, overriding whatever buildAssetRiskInput picked from the
	// asset's broader open-finding set — phase10.md §38 enriches THIS
	// finding, not just its asset in general.
	input.HighestFindingSeverity = risk.Severity(f.Severity)
	input.HighestFindingConfidenceHigh = f.Confidence.Level() == domainfinding.LevelHigh || f.Confidence.Level() == domainfinding.LevelVeryHigh

	result := s.scorer.Calculate(input)
	riskScore, err := s.persistRiskScore(ctx, f.TargetID, domainintel.EntityFinding, findingID, result)
	if err != nil {
		return FindingEnrichment{}, err
	}

	return FindingEnrichment{Finding: f, Asset: assetEnrichment, Risk: riskScore}, nil
}

func bestIntel(lookups []LookupReport) intelligence.AggregatedResult {
	var best intelligence.AggregatedResult
	for _, l := range lookups {
		if l.Aggregated.Verdict.Rank() > best.Verdict.Rank() {
			best = l.Aggregated
		}
	}
	return best
}

// InvestigationEnrichment is EnrichInvestigation's result.
type InvestigationEnrichment struct {
	InvestigationID   uuid.UUID
	HighestRiskAssets []domainintel.RiskScore
	Risk              domainintel.RiskScore
}

// EnrichInvestigation computes an investigation-level risk context from
// every asset/finding attached to it (phase10.md §39/§40): each
// attached asset is enriched, and the investigation's own risk score
// takes the highest-risk contributing asset's factors plus its own
// intelligence signals — never claiming a higher score than any evidence
// actually supports.
func (s *Service) EnrichInvestigation(ctx context.Context, investigationID uuid.UUID) (InvestigationEnrichment, error) {
	inv, err := s.investigations.GetByID(ctx, investigationID)
	if err != nil {
		return InvestigationEnrichment{}, err
	}
	targetID := inv.TargetID

	evidence, err := s.investigations.ListEvidence(ctx, investigationrepo.EvidenceListFilter{
		InvestigationID: investigationID, Pagination: pagination.Params{Limit: pagination.MaxLimit},
	})
	if err != nil {
		return InvestigationEnrichment{}, err
	}

	assetIDs := map[uuid.UUID]bool{}
	for _, e := range evidence.Items {
		switch e.SourceType {
		case domaininvestigation.EntityAsset:
			assetIDs[e.SourceID] = true
		case domaininvestigation.EntityFinding:
			f, err := s.findings.GetByID(ctx, e.SourceID)
			if err == nil {
				assetIDs[f.AssetID] = true
			}
		}
	}
	if len(assetIDs) == 0 {
		return InvestigationEnrichment{}, apperrors.NewValidation("investigation has no attached assets or findings to enrich", nil)
	}

	var scores []domainintel.RiskScore
	var highest domainintel.RiskScore
	for assetID := range assetIDs {
		enrichment, err := s.EnrichAsset(ctx, assetID)
		if err != nil {
			s.logger.Error("intelligence_investigation_asset_enrich_failed", "investigation_id", investigationID, "asset_id", assetID, "error", err)
			continue
		}
		scores = append(scores, enrichment.Risk)
		if enrichment.Risk.Score >= highest.Score {
			highest = enrichment.Risk
		}
	}

	explanation := fmt.Sprintf("Investigation risk reflects %d contributing asset(s); highest individual asset risk score: %d.\n\n%s",
		len(scores), highest.Score, highest.Explanation)
	factors := append([]domainintel.RiskFactor{}, highest.Factors...)

	investigationScore := domainintel.RiskScore{
		TargetID: targetID, EntityType: domainintel.EntityInvestigation, EntityID: investigationID,
		Score: highest.Score, Severity: highest.Severity, Confidence: highest.Confidence,
		ModelVersion: risk.ModelVersion, Factors: factors, Explanation: explanation, CalculatedAt: time.Now().UTC(),
	}
	saved, err := s.risks.CreateRiskScore(ctx, investigationScore)
	if err != nil {
		return InvestigationEnrichment{}, err
	}

	return InvestigationEnrichment{InvestigationID: investigationID, HighestRiskAssets: scores, Risk: saved}, nil
}

// SetCriticality records an analyst's explicit asset-criticality
// judgment (phase10.md §36) — never inferred by this platform.
func (s *Service) SetCriticality(ctx context.Context, assetID, targetID uuid.UUID, criticality domainintel.Criticality, setBy string) (domainintel.AssetCriticality, error) {
	c := domainintel.AssetCriticality{AssetID: assetID, TargetID: targetID, Criticality: criticality, SetBy: setBy, SetAt: time.Now().UTC()}
	if err := c.Validate(); err != nil {
		return domainintel.AssetCriticality{}, apperrors.NewValidation("invalid asset criticality", err)
	}
	return s.crit.SetCriticality(ctx, c)
}

// RiskHistory returns every risk score ever calculated for an entity,
// newest first (phase10.md §46).
func (s *Service) RiskHistory(ctx context.Context, entityType domainintel.EntityType, entityID uuid.UUID, params pagination.Params) (pagination.Page[domainintel.RiskScore], error) {
	return s.risks.ListRiskHistory(ctx, entityType, entityID, params)
}

// LatestRisk returns the most recently calculated risk score for an
// entity.
func (s *Service) LatestRisk(ctx context.Context, entityType domainintel.EntityType, entityID uuid.UUID) (domainintel.RiskScore, error) {
	return s.risks.GetLatestRiskScore(ctx, entityType, entityID)
}
