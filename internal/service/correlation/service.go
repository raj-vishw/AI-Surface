// Package correlation bridges internal/correlation's self-contained
// strategy engine to persistence and to Phase 8/9/10/11's own
// repositories — the same "engine is self-contained, the service layer
// bridges it to the domain model and the database" split
// internal/service/rule follows for Phase 11. It assembles
// internal/correlation.Observation values entirely from data Phase
// 2/7/8/10/11 already persisted (assets, endpoints, findings,
// intelligence records, detection matches, alerts — see observations.go),
// runs the correlation engine over them, and records the result — the
// resulting graph, score, confidence, and optional attack chain — through
// internal/repository/correlation.
package correlation

import (
	"context"
	"log/slog"

	"ai-recon-platform/internal/correlation"
	"ai-recon-platform/internal/correlation/strategies"
	"ai-recon-platform/internal/database"
	domaintarget "ai-recon-platform/internal/domain/target"
	correlationrepo "ai-recon-platform/internal/repository/correlation"
	endpointrepo "ai-recon-platform/internal/repository/endpoint"
	findingrepo "ai-recon-platform/internal/repository/finding"
	fingerprintrepo "ai-recon-platform/internal/repository/fingerprint"
	intelrepo "ai-recon-platform/internal/repository/intelligence"
	investigationrepo "ai-recon-platform/internal/repository/investigation"
	rulerepo "ai-recon-platform/internal/repository/rule"
	assetsvc "ai-recon-platform/internal/service/asset"
	targetsvc "ai-recon-platform/internal/service/target"
)

// registerBuiltinStrategies registers Phase 12's built-in correlation
// strategies (phase12.md §22) — a thin wrapper so NewService doesn't need
// its own import-cycle-aware knowledge of the strategies package.
func registerBuiltinStrategies(registry *correlation.StrategyRegistry) error {
	return strategies.RegisterAll(registry)
}

// Service orchestrates every correlation/attack-chain operation.
type Service struct {
	pool *database.Pool

	targets      *targetsvc.Service
	assets       *assetsvc.Service
	findings     findingrepo.Repository
	endpoints    endpointrepo.Repository
	fingerprints fingerprintrepo.Repository
	intelligence intelrepo.RecordRepository

	rules    rulerepo.Repository
	matches  rulerepo.MatchRepository
	evidence rulerepo.EvidenceRepository
	alerts   rulerepo.AlertRepository

	investigations *investigationrepo.PostgresRepository

	correlations correlationrepo.Repository
	nodes        correlationrepo.NodeRepository
	edges        correlationrepo.EdgeRepository
	chains       correlationrepo.ChainRepository
	stages       correlationrepo.StageRepository

	engine *correlation.Engine
	cfg    correlation.Config
	logger *slog.Logger
}

// NewService builds a Service. targets/assets are Phase 2's services;
// findings/endpoints/fingerprints/intelligence/rules-matches-alerts/
// investigations are Phase 7/8/9/10/11's repositories, all reused
// directly (never duplicated — phase12.md's own "do not duplicate
// existing functionality" instruction).
func NewService(pool *database.Pool, targets *targetsvc.Service, assets *assetsvc.Service, cfg correlation.Config, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	ruleRepo := rulerepo.NewPostgresRepository(pool)
	correlationRepo := correlationrepo.NewPostgresRepository(pool)

	registry := correlation.NewStrategyRegistry()
	if err := registerBuiltinStrategies(registry); err != nil {
		logger.Error("correlation_strategy_registration_failed", "error", err)
	}

	return &Service{
		pool: pool, targets: targets, assets: assets,
		findings:     findingrepo.NewPostgresRepository(pool),
		endpoints:    endpointrepo.NewPostgresRepository(pool),
		fingerprints: fingerprintrepo.NewPostgresRepository(pool),
		intelligence: intelrepo.NewPostgresRepository(pool),
		rules:        ruleRepo, matches: ruleRepo, evidence: ruleRepo, alerts: ruleRepo,
		investigations: investigationrepo.NewPostgresRepository(pool),
		correlations:   correlationRepo, nodes: correlationRepo, edges: correlationRepo, chains: correlationRepo, stages: correlationRepo,
		engine: correlation.NewEngine(registry), cfg: cfg, logger: logger,
	}
}

// ResolveTarget loads the target for (targetType, targetValue) — the
// same convention every other phase's service uses.
func (s *Service) ResolveTarget(ctx context.Context, targetType domaintarget.Type, targetValue string) (domaintarget.Target, error) {
	return s.targets.GetByValue(ctx, targetType, targetValue)
}
