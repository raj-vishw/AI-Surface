package investigation

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	domainfp "ai-surface-platform/internal/domain/fingerprint"
	domaininvestigation "ai-surface-platform/internal/domain/investigation"
	"ai-surface-platform/internal/investigation"
	fingerprintrepo "ai-surface-platform/internal/repository/fingerprint"
	investigationrepo "ai-surface-platform/internal/repository/investigation"
	"ai-surface-platform/internal/repository/pagination"
)

// CorrelateResult is one non-dry-run Correlate call's outcome.
type CorrelateResult struct {
	Relationships []domaininvestigation.Relationship
	RuleErrors    []investigation.RuleError
	FindingsUsed  int
}

// CorrelateDryRunReport is returned instead of a CorrelateResult when
// dryRun is true (phase9.md §80) — no relationship is persisted.
type CorrelateDryRunReport struct {
	InvestigationID uuid.UUID
	Rules           []string
	FindingsCount   int
	WouldCreate     []domaininvestigation.Relationship
}

// Correlate builds a investigation.Input from every finding currently
// attached to investigationID (plus their sibling assets/endpoints/
// technology fingerprints), runs the correlation engine, and — unless
// dryRun — persists every resulting relationship (phase9.md §13/§55/§80).
func (s *Service) Correlate(ctx context.Context, investigationID uuid.UUID, cfg investigation.Config, dryRun bool) (*CorrelateResult, *CorrelateDryRunReport, error) {
	findings, err := s.ListFindings(ctx, investigationID)
	if err != nil {
		return nil, nil, fmt.Errorf("loading attached findings: %w", err)
	}

	input := investigation.Input{Config: cfg}
	assetIDs := map[uuid.UUID]bool{}
	for _, f := range findings {
		obs := investigation.FindingObservation{
			ID: f.ID, AssetID: f.AssetID, EndpointID: f.EndpointID, DetectorID: f.DetectorID,
			Category: string(f.Category), Severity: string(f.Severity), ScanID: f.ScanID,
			FirstSeen: f.FirstSeen, LastSeen: f.LastSeen,
		}
		input.Findings = append(input.Findings, obs)
		assetIDs[f.AssetID] = true
	}

	input.Assets = map[uuid.UUID]investigation.AssetObservation{}
	input.Endpoints = map[uuid.UUID]investigation.EndpointObservation{}
	for assetID := range assetIDs {
		a, err := s.assets.GetByID(ctx, assetID)
		if err != nil {
			s.logger.Error("investigation_correlate_asset_load_failed", "investigation_id", investigationID, "asset_id", assetID, "error", err)
			continue
		}
		hostname, ip := "", ""
		if a.Hostname != nil {
			hostname = *a.Hostname
		}
		if a.IP != nil {
			ip = *a.IP
		}
		input.Assets[assetID] = investigation.AssetObservation{
			ID: a.ID, Hostname: hostname, IP: ip, Type: string(a.Type), FirstSeen: a.FirstSeen, LastSeen: a.LastSeen,
		}

		techPage, err := s.fingerprints.List(ctx, fingerprintrepo.ListFilter{
			AssetID: assetID, Status: domainfp.StatusActive, Pagination: pagination.Params{Limit: pagination.MaxLimit},
		})
		if err != nil {
			s.logger.Error("investigation_correlate_fingerprint_load_failed", "investigation_id", investigationID, "asset_id", assetID, "error", err)
		} else {
			for _, fp := range techPage.Items {
				input.Technologies = append(input.Technologies, investigation.TechnologyObservation{
					ID: fp.ID, AssetID: fp.AssetID, Category: string(fp.Category), Technology: fp.Technology,
					Version: fp.Version, FirstSeen: fp.FirstSeen, LastSeen: fp.LastSeen,
				})
			}
		}
	}
	for _, f := range findings {
		if f.EndpointID == nil {
			continue
		}
		if _, ok := input.Endpoints[*f.EndpointID]; ok {
			continue
		}
		ep, err := s.endpoints.GetByID(ctx, *f.EndpointID)
		if err != nil {
			s.logger.Error("investigation_correlate_endpoint_load_failed", "investigation_id", investigationID, "endpoint_id", *f.EndpointID, "error", err)
			continue
		}
		input.Endpoints[ep.ID] = investigation.EndpointObservation{ID: ep.ID, AssetID: ep.AssetID, Path: ep.Path, FirstSeen: ep.FirstSeen, LastSeen: ep.LastSeen}
	}

	if dryRun {
		names := make([]string, 0)
		for _, r := range s.registry.Active() {
			if cfg.RuleEnabled(r.ID()) {
				names = append(names, r.ID())
			}
		}
		return nil, &CorrelateDryRunReport{InvestigationID: investigationID, Rules: names, FindingsCount: len(findings)}, nil
	}

	engineResult := s.engine.Correlate(ctx, input)
	inv, err := s.investigations.GetByID(ctx, investigationID)
	if err != nil {
		return nil, nil, err
	}

	result := &CorrelateResult{RuleErrors: engineResult.Errors, FindingsUsed: len(findings)}
	for _, rel := range engineResult.Relationships {
		persisted, err := s.persistRelationship(ctx, inv, rel, cfg.EffectiveThreshold())
		if err != nil {
			s.logger.Error("investigation_relationship_persist_failed", "investigation_id", investigationID, "rule_id", rel.RuleID, "error", err)
			continue
		}
		result.Relationships = append(result.Relationships, persisted)
	}
	return result, nil, nil
}

func (s *Service) persistRelationship(ctx context.Context, inv domaininvestigation.Investigation, rel investigation.Relationship, threshold int) (domaininvestigation.Relationship, error) {
	status := domaininvestigation.RelationshipCandidate
	if rel.Score >= threshold {
		status = domaininvestigation.RelationshipConfirmed
	}

	domainRel := domaininvestigation.Relationship{
		InvestigationID: inv.ID,
		SourceType:      domaininvestigation.EntityType(rel.SourceType), SourceID: rel.SourceID,
		TargetType: domaininvestigation.EntityType(rel.TargetType), TargetID: rel.TargetID,
		Type: domaininvestigation.RelationshipType(rel.Type), Status: status,
		Score: rel.Score, Confidence: domaininvestigation.Confidence(investigation.ConfidenceForScore(rel.Score)),
		Explanation: rel.Explanation, Signals: rel.Signals, RuleID: rel.RuleID, RuleVersion: rel.RuleVersion,
	}
	if err := domainRel.Validate(); err != nil {
		return domaininvestigation.Relationship{}, err
	}

	result, created, err := s.relationships.UpsertRelationship(ctx, domainRel)
	if err != nil {
		return domaininvestigation.Relationship{}, err
	}
	if created && status == domaininvestigation.RelationshipConfirmed {
		s.recordEvent(ctx, inv, domaininvestigation.EventRelationshipCreated, rel.Explanation, "", "system", nil)
	}
	return result, nil
}

// ListRelationships returns a page of an investigation's relationships.
func (s *Service) ListRelationships(ctx context.Context, investigationID uuid.UUID, status domaininvestigation.RelationshipStatus, p pagination.Params) (pagination.Page[domaininvestigation.Relationship], error) {
	return s.relationships.ListRelationships(ctx, investigationrepo.RelationshipListFilter{InvestigationID: investigationID, Status: status, Pagination: p})
}
