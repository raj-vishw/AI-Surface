// Package reporting bridges internal/reporting's report-building engine
// to persistence and to Phase 2/8/9/10/11/12/13's own repositories —
// the same "engine is self-contained, the service layer bridges it to
// the domain model and the database" split every prior phase's service
// package follows. It never duplicates any existing model: every report
// section is built by reading Phase 2-13's own repositories (through
// internal/analytics for aggregates, and directly for narrative detail),
// never a second copy of that data.
package reporting

import (
	"log/slog"

	"ai-recon-platform/internal/analytics"
	"ai-recon-platform/internal/database"
	assetrepo "ai-recon-platform/internal/repository/asset"
	correlationrepo "ai-recon-platform/internal/repository/correlation"
	findingrepo "ai-recon-platform/internal/repository/finding"
	intelrepo "ai-recon-platform/internal/repository/intelligence"
	investigationrepo "ai-recon-platform/internal/repository/investigation"
	reportingrepo "ai-recon-platform/internal/repository/reporting"
	rulerepo "ai-recon-platform/internal/repository/rule"
)

// Service orchestrates every report/evidence-package/control-evidence
// operation.
type Service struct {
	pool *database.Pool

	analytics *analytics.Service

	investigations investigationrepo.Repository
	evidence       investigationrepo.EvidenceRepository
	timeline       investigationrepo.TimelineRepository

	assets   assetrepo.Repository
	findings findingrepo.Repository

	rules   rulerepo.Repository
	matches rulerepo.MatchRepository
	alerts  rulerepo.AlertRepository

	correlations correlationrepo.Repository
	nodes        correlationrepo.NodeRepository
	edges        correlationrepo.EdgeRepository
	chains       correlationrepo.ChainRepository
	stages       correlationrepo.StageRepository

	intelRecords intelrepo.RecordRepository
	risk         intelrepo.RiskRepository

	reports  reportingrepo.ReportRepository
	packages reportingrepo.PackageRepository
	items    reportingrepo.ItemRepository
	controls reportingrepo.ControlEvidenceRepository

	logger *slog.Logger
}

// NewService builds a Service. Every repository parameter is reused
// directly from its owning phase.
func NewService(
	pool *database.Pool, analyticsSvc *analytics.Service,
	investigations investigationrepo.Repository, evidence investigationrepo.EvidenceRepository, timeline investigationrepo.TimelineRepository,
	assets assetrepo.Repository, findings findingrepo.Repository,
	rules rulerepo.Repository, matches rulerepo.MatchRepository, alerts rulerepo.AlertRepository,
	correlations correlationrepo.Repository, nodes correlationrepo.NodeRepository, edges correlationrepo.EdgeRepository,
	chains correlationrepo.ChainRepository, stages correlationrepo.StageRepository,
	intelRecords intelrepo.RecordRepository, risk intelrepo.RiskRepository,
	reports reportingrepo.ReportRepository, packages reportingrepo.PackageRepository,
	items reportingrepo.ItemRepository, controls reportingrepo.ControlEvidenceRepository,
	logger *slog.Logger,
) *Service {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{
		pool: pool, analytics: analyticsSvc,
		investigations: investigations, evidence: evidence, timeline: timeline,
		assets: assets, findings: findings,
		rules: rules, matches: matches, alerts: alerts,
		correlations: correlations, nodes: nodes, edges: edges, chains: chains, stages: stages,
		intelRecords: intelRecords, risk: risk,
		reports: reports, packages: packages, items: items, controls: controls,
		logger: logger,
	}
}
