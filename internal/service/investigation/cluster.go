package investigation

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	domainfinding "ai-surface-platform/internal/domain/finding"
	domaininvestigation "ai-surface-platform/internal/domain/investigation"
	domaintarget "ai-surface-platform/internal/domain/target"
	apperrors "ai-surface-platform/internal/errors"
	findingrepo "ai-surface-platform/internal/repository/finding"
	investigationrepo "ai-surface-platform/internal/repository/investigation"
	"ai-surface-platform/internal/repository/pagination"
)

// SuggestClusters scans a target's currently-open findings and proposes
// one IncidentCluster per asset with two or more open findings
// (phase9.md §40/§41) — never auto-creating an Investigation; every
// cluster starts ClusterSuggested and requires an explicit analyst Accept
// (phase9.md §40's "do NOT automatically merge investigations created by
// analysts. Automatic grouping should produce a suggested incident
// cluster which an analyst can accept").
func (s *Service) SuggestClusters(ctx context.Context, targetType domaintarget.Type, targetValue string) ([]domaininvestigation.IncidentCluster, error) {
	target, err := s.targets.GetByValue(ctx, targetType, targetValue)
	if err != nil {
		return nil, fmt.Errorf("loading target: %w", err)
	}

	byAsset := map[uuid.UUID][]domainfinding.Finding{}
	cursor := ""
	for {
		page, err := s.findings.List(ctx, findingrepo.ListFilter{
			TargetID: target.ID, Status: domainfinding.StatusOpen, Pagination: pagination.Params{Limit: pagination.MaxLimit, Cursor: cursor},
		})
		if err != nil {
			return nil, fmt.Errorf("listing open findings: %w", err)
		}
		for _, f := range page.Items {
			byAsset[f.AssetID] = append(byAsset[f.AssetID], f)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	var out []domaininvestigation.IncidentCluster
	for assetID, findingsForAsset := range byAsset {
		if len(findingsForAsset) < 2 {
			continue
		}
		asset, err := s.assets.GetByID(ctx, assetID)
		if err != nil {
			continue
		}
		label := "asset"
		if asset.Hostname != nil && *asset.Hostname != "" {
			label = *asset.Hostname
		} else if asset.URL != nil && *asset.URL != "" {
			label = *asset.URL
		}

		cluster := domaininvestigation.IncidentCluster{
			TargetID: target.ID, Title: fmt.Sprintf("%d open findings on %s", len(findingsForAsset), label),
			Confidence: domaininvestigation.ConfidenceLow, Status: domaininvestigation.ClusterSuggested,
		}
		if err := cluster.Validate(); err != nil {
			continue
		}
		created, err := s.clusters.CreateCluster(ctx, cluster)
		if err != nil {
			s.logger.Error("investigation_cluster_suggest_failed", "target_id", target.ID, "asset_id", assetID, "error", err)
			continue
		}
		for _, f := range findingsForAsset {
			item := domaininvestigation.ClusterItem{ClusterID: created.ID, SourceType: domaininvestigation.EntityFinding, SourceID: f.ID}
			if _, err := s.clusters.AddClusterItem(ctx, item); err != nil {
				s.logger.Error("investigation_cluster_item_add_failed", "cluster_id", created.ID, "finding_id", f.ID, "error", err)
			}
		}
		out = append(out, created)
	}
	return out, nil
}

// GetCluster returns one incident cluster.
func (s *Service) GetCluster(ctx context.Context, id uuid.UUID) (domaininvestigation.IncidentCluster, error) {
	return s.clusters.GetCluster(ctx, id)
}

// ListClusters returns a page of incident clusters.
func (s *Service) ListClusters(ctx context.Context, filter investigationrepo.ClusterListFilter) (pagination.Page[domaininvestigation.IncidentCluster], error) {
	return s.clusters.ListClusters(ctx, filter)
}

// ListClusterItems returns every item belonging to a cluster.
func (s *Service) ListClusterItems(ctx context.Context, clusterID uuid.UUID) ([]domaininvestigation.ClusterItem, error) {
	return s.clusters.ListClusterItems(ctx, clusterID)
}

// AcceptCluster converts a suggested cluster into a real Investigation
// (phase9.md §41's "analysts can convert/accept a cluster into an
// investigation"), attaching every clustered item as evidence.
func (s *Service) AcceptCluster(ctx context.Context, clusterID uuid.UUID, actorID string) (domaininvestigation.Investigation, error) {
	cluster, err := s.clusters.GetCluster(ctx, clusterID)
	if err != nil {
		return domaininvestigation.Investigation{}, err
	}
	if cluster.Status != domaininvestigation.ClusterSuggested {
		return domaininvestigation.Investigation{}, apperrors.NewValidation("cluster is not in suggested status", nil)
	}

	inv, err := s.investigations.Create(ctx, domaininvestigation.Investigation{
		TargetID: cluster.TargetID, Title: cluster.Title,
		Description: "Created from accepted incident cluster.",
		Status:      domaininvestigation.StatusNew, Confidence: cluster.Confidence, CreatedBy: actorID,
	})
	if err != nil {
		return domaininvestigation.Investigation{}, err
	}
	s.recordEvent(ctx, inv, domaininvestigation.EventInvestigationCreated, "Investigation created from accepted cluster.", "", actorID, nil)

	items, err := s.clusters.ListClusterItems(ctx, clusterID)
	if err != nil {
		s.logger.Error("investigation_cluster_items_load_failed", "cluster_id", clusterID, "error", err)
	}
	for _, item := range items {
		if item.SourceType == domaininvestigation.EntityFinding {
			if _, err := s.AttachFinding(ctx, inv.ID, item.SourceID, domaininvestigation.RelationCorrelated, actorID); err != nil {
				s.logger.Error("investigation_cluster_finding_attach_failed", "investigation_id", inv.ID, "finding_id", item.SourceID, "error", err)
			}
			continue
		}
		if _, err := s.AttachEvidence(ctx, inv.ID, item.SourceType, item.SourceID, actorID); err != nil {
			s.logger.Error("investigation_cluster_evidence_attach_failed", "investigation_id", inv.ID, "source_id", item.SourceID, "error", err)
		}
	}

	invID := inv.ID
	if _, err := s.clusters.UpdateClusterStatus(ctx, clusterID, domaininvestigation.ClusterAccepted, &invID); err != nil {
		s.logger.Error("investigation_cluster_status_update_failed", "cluster_id", clusterID, "error", err)
	}

	return s.GetByID(ctx, inv.ID)
}

// RejectCluster marks a cluster rejected — preserved, never deleted
// (phase9.md §42).
func (s *Service) RejectCluster(ctx context.Context, clusterID uuid.UUID) (domaininvestigation.IncidentCluster, error) {
	return s.clusters.UpdateClusterStatus(ctx, clusterID, domaininvestigation.ClusterRejected, nil)
}
