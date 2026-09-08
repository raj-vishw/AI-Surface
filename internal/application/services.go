package application

// services.go builds every service/repository internal/api's REST
// handlers need, once, at server startup — mirroring exactly the
// wiring each `cmd/cli/commands` buildXService function already does
// for its own CLI invocation (see e.g. cmd/cli/commands/ai.go,
// reports.go, correlation.go, detection.go, investigate.go, intel.go),
// just done once for a long-lived process instead of once per CLI
// invocation. No engine/service package is modified to support this —
// every constructor used below already existed for the CLI.

import (
	"log/slog"

	engineai "ai-recon-platform/internal/ai"
	"ai-recon-platform/internal/ai/providers/mock"
	"ai-recon-platform/internal/ai/providers/openai"
	"ai-recon-platform/internal/analytics"
	"ai-recon-platform/internal/api"
	"ai-recon-platform/internal/config"
	"ai-recon-platform/internal/correlation"
	"ai-recon-platform/internal/database"
	"ai-recon-platform/internal/httpclient"
	"ai-recon-platform/internal/intelligence"
	"ai-recon-platform/internal/intelligence/providers"
	"ai-recon-platform/internal/intelligence/risk"
	"ai-recon-platform/internal/investigation"
	investigationcorrelation "ai-recon-platform/internal/investigation/correlation"
	airepo "ai-recon-platform/internal/repository/ai"
	analyticsrepo "ai-recon-platform/internal/repository/analytics"
	assetrepo "ai-recon-platform/internal/repository/asset"
	correlationrepo "ai-recon-platform/internal/repository/correlation"
	findingrepo "ai-recon-platform/internal/repository/finding"
	fingerprintrepo "ai-recon-platform/internal/repository/fingerprint"
	intelrepo "ai-recon-platform/internal/repository/intelligence"
	investigationrepo "ai-recon-platform/internal/repository/investigation"
	reportingrepo "ai-recon-platform/internal/repository/reporting"
	rulerepo "ai-recon-platform/internal/repository/rule"
	"ai-recon-platform/internal/ruleengine"
	aisvc "ai-recon-platform/internal/service/ai"
	assetsvc "ai-recon-platform/internal/service/asset"
	correlationsvc "ai-recon-platform/internal/service/correlation"
	intelligencesvc "ai-recon-platform/internal/service/intelligence"
	investigationsvc "ai-recon-platform/internal/service/investigation"
	reportingsvc "ai-recon-platform/internal/service/reporting"
	rulesvc "ai-recon-platform/internal/service/rule"
	targetsvc "ai-recon-platform/internal/service/target"
)

// Services holds every service/repository the REST API layer
// (internal/api) reads from or mutates through. Read-only listing that no
// service method wraps goes through the raw repository directly (e.g.
// IntelRecords, ToolCalls) — the same "grab the repo directly alongside
// the service" pattern several buildXService functions already use
// (cmd/cli/commands/ai.go, reports.go).
type Services struct {
	Targets        *targetsvc.Service
	Assets         *assetsvc.Service
	Findings       findingrepo.Repository
	Fingerprints   fingerprintrepo.Repository
	Rules          *rulesvc.Service
	Correlations   *correlationsvc.Service
	Investigation  *investigationsvc.Service
	Intelligence   *intelligencesvc.Service
	IntelRecords   intelrepo.RecordRepository
	AI             *aisvc.Service
	AIToolCalls    airepo.ToolCallRepository
	AIRequests     airepo.RequestRepository
	AIResponses    airepo.ResponseRepository
	Reporting      *reportingsvc.Service
	ReportPackages reportingrepo.PackageRepository
	Analytics      *analytics.Service
}

// toRiskWeights mirrors cmd/cli/commands/intel.go's own private helper of
// the same name — a small, pure config-shape conversion duplicated here
// rather than exported across a CLI/server boundary neither package
// otherwise depends on.
func toRiskWeights(w config.IntelligenceRiskWeightsConfig) risk.Weights {
	return risk.Weights{
		FindingSeverityCritical: w.FindingSeverityCritical, FindingSeverityHigh: w.FindingSeverityHigh,
		FindingSeverityMedium: w.FindingSeverityMedium, FindingSeverityLow: w.FindingSeverityLow,
		FindingSeverityInformational: w.FindingSeverityInformational, FindingConfidenceHigh: w.FindingConfidenceHigh,
		ExposureInternetFacing: w.ExposureInternetFacing, ExposureOpenServicePerUnit: w.ExposureOpenServicePerUnit,
		ExposureOpenServiceMax: w.ExposureOpenServiceMax, ExposureSensitiveEndpoint: w.ExposureSensitiveEndpoint,
		ExposureExposedAPI: w.ExposureExposedAPI, VulnerabilityConfirmed: w.VulnerabilityConfirmed,
		VulnerabilityProbable: w.VulnerabilityProbable, IntelligenceMalicious: w.IntelligenceMalicious,
		IntelligenceSuspicious: w.IntelligenceSuspicious, AssetCriticalityCritical: w.AssetCriticalityCritical,
		AssetCriticalityHigh: w.AssetCriticalityHigh, AssetCriticalityNormal: w.AssetCriticalityNormal,
		AssetCriticalityLow: w.AssetCriticalityLow, RecentChange: w.RecentChange,
	}
}

// buildServices wires every service the API needs against pool, mirroring
// each CLI command's own construction. logger is shared; cfg supplies
// every engine's own configuration exactly as the CLI reads it.
func buildServices(pool *database.Pool, cfg *config.Config, logger *slog.Logger) (*Services, error) {
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)

	findingRepo := findingrepo.NewPostgresRepository(pool)
	fingerprintRepo := fingerprintrepo.NewPostgresRepository(pool)
	ruleRepo := rulerepo.NewPostgresRepository(pool)
	correlationRepo := correlationrepo.NewPostgresRepository(pool)
	investigationRepo := investigationrepo.NewPostgresRepository(pool)
	intelRepo := intelrepo.NewPostgresRepository(pool)
	aiRepo := airepo.NewPostgresRepository(pool)
	reportingRepo := reportingrepo.NewPostgresRepository(pool)

	ruleEngineCfg := ruleengine.Config{
		MaxConcurrency: cfg.DetectionRules.Evaluation.MaxConcurrency, EvaluationTimeout: cfg.DetectionRules.Evaluation.Timeout,
		ClockSkew: cfg.DetectionRules.Evaluation.ClockSkew, SuppressionWindow: cfg.DetectionRules.SuppressionDefaultWindow,
		HistoricalMaxRange: cfg.DetectionRules.Historical.MaxRange,
	}
	rules := rulesvc.NewService(pool, targets, assets, ruleEngineCfg, logger)

	correlationEngineCfg := correlation.Config{
		TemporalWindow: cfg.Correlation.Temporal.DefaultWindow,
		MaxNodes:       cfg.Correlation.Graph.MaxNodes, MaxEdges: cfg.Correlation.Graph.MaxEdges, MaxDepth: cfg.Correlation.Graph.MaxDepth,
		MaxCandidates: cfg.Correlation.MaxCandidates, HistoricalMaxRange: cfg.Correlation.HistoricalMaxRange,
	}
	correlations := correlationsvc.NewService(pool, targets, assets, correlationEngineCfg, logger)

	investigationRegistry := investigation.NewRegistry()
	if err := investigationcorrelation.RegisterAll(investigationRegistry); err != nil {
		return nil, err
	}
	investigations := investigationsvc.NewService(pool, targets, assets, investigationRegistry, logger)

	datasetSource := providers.NewDatasetSource()
	intelRegistry := intelligence.NewRegistry()
	if err := intelRegistry.Register(providers.NewLocalProvider(datasetSource)); err != nil {
		return nil, err
	}
	if err := intelRegistry.Register(providers.NewDNSProvider(datasetSource)); err != nil {
		return nil, err
	}
	if err := intelRegistry.Register(providers.NewCertificateProvider(datasetSource)); err != nil {
		return nil, err
	}
	if err := intelRegistry.Register(providers.NewTechnologyProvider(datasetSource)); err != nil {
		return nil, err
	}
	if cfg.Intelligence.ThreatFeed.BaseURL != "" {
		client := httpclient.NewFromConfig(cfg.HTTPClient)
		feedCfg := providers.ThreatFeedConfig{
			BaseURL: cfg.Intelligence.ThreatFeed.BaseURL, APIKeyEnv: cfg.Intelligence.ThreatFeed.APIKeyEnv,
			RequestsPerSecond: cfg.Intelligence.ThreatFeed.RequestsPerSecond, MaxRetries: cfg.Intelligence.ThreatFeed.MaxRetries,
		}
		if err := intelRegistry.Register(providers.NewThreatFeedProvider(client, feedCfg)); err != nil {
			return nil, err
		}
	}
	for id, enabled := range cfg.Intelligence.Providers {
		intelRegistry.SetEnabled(id, enabled)
	}
	intelEngineCfg := intelligence.Config{
		Providers: cfg.Intelligence.Providers, ProviderTimeout: cfg.Intelligence.ProviderTimeout,
		ReputationTTL: cfg.Intelligence.ReputationTTL, VulnerabilityTTL: cfg.Intelligence.VulnerabilityTTL,
		ExternalEnrichmentEnabled: cfg.Intelligence.External.Enabled,
	}
	weights := toRiskWeights(cfg.Intelligence.Risk.Weights)
	intelSvc := intelligencesvc.NewService(pool, targets, assets, intelRegistry, datasetSource, intelEngineCfg, weights, logger)

	aiProviders := engineai.NewProviderRegistry()
	if err := aiProviders.Register(mock.New()); err != nil {
		return nil, err
	}
	if cfg.AI.Provider.Name == "openai" {
		if err := aiProviders.Register(openai.New(openai.Config{
			Endpoint: cfg.AI.Provider.Endpoint, Model: cfg.AI.Provider.Model,
			APIKeyEnv: cfg.AI.Provider.APIKeyEnv, Timeout: cfg.AI.Timeouts.Request,
		})); err != nil {
			return nil, err
		}
	}
	aiSvcCfg := aisvc.Config{
		RequestTimeout: cfg.AI.Timeouts.Request, ToolTimeout: cfg.AI.Timeouts.Tool,
		MaxRetries: cfg.AI.Retries.Max, RetryBackoff: cfg.AI.Retries.Backoff,
		Limits:          engineai.Limits{MaxFactsPerType: cfg.AI.Limits.MaxFactsPerType, MaxTotalFacts: cfg.AI.Limits.MaxTotalFacts},
		DefaultProvider: cfg.AI.Provider.Name,
		RateLimit: aisvc.RateLimitConfig{
			PerUserPerMinute: cfg.AI.RateLimit.PerUserPerMinute, PerTargetPerMinute: cfg.AI.RateLimit.PerTargetPerMinute,
			MaxConcurrent: cfg.AI.RateLimit.MaxConcurrent,
		},
	}
	ai := aisvc.NewService(
		pool, targets,
		investigationRepo, investigationRepo, investigationRepo, investigationRepo,
		findingRepo, assetrepo.NewPostgresRepository(pool),
		ruleRepo, ruleRepo, ruleRepo,
		correlationRepo, correlationRepo, correlationRepo, correlationRepo, correlationRepo,
		intelRepo, intelRepo,
		aiRepo, aiRepo, aiRepo, aiRepo, aiRepo,
		aiProviders, aiSvcCfg, logger,
	)

	analyticsSvc := analytics.NewService(analyticsrepo.NewPostgresRepository(pool), analytics.NewCache(analytics.DefaultCacheTTL))

	reporting := reportingsvc.NewService(
		pool, analyticsSvc,
		investigationRepo, investigationRepo, investigationRepo,
		assetrepo.NewPostgresRepository(pool), findingRepo,
		ruleRepo, ruleRepo, ruleRepo,
		correlationRepo, correlationRepo, correlationRepo, correlationRepo, correlationRepo,
		intelRepo, intelRepo,
		reportingRepo, reportingRepo, reportingRepo, reportingRepo,
		logger,
	)

	return &Services{
		Targets: targets, Assets: assets, Findings: findingRepo, Fingerprints: fingerprintRepo,
		Rules: rules, Correlations: correlations, Investigation: investigations,
		Intelligence: intelSvc, IntelRecords: intelRepo,
		AI: ai, AIToolCalls: aiRepo, AIRequests: aiRepo, AIResponses: aiRepo,
		Reporting: reporting, ReportPackages: reportingRepo, Analytics: analyticsSvc,
	}, nil
}

// APIDeps converts Services into the shape internal/api.NewRouter
// expects — kept as an explicit conversion (rather than making
// internal/api import this package, or vice versa) so cmd/cli never
// pulls in an HTTP dependency merely by sharing internal/service/*.
func (s *Services) APIDeps() api.Deps {
	return api.Deps{
		Targets: s.Targets, Assets: s.Assets, Findings: s.Findings, Fingerprints: s.Fingerprints,
		Rules: s.Rules, Correlations: s.Correlations, Investigation: s.Investigation,
		Intelligence: s.Intelligence, IntelRecords: s.IntelRecords,
		AI: s.AI, AIToolCalls: s.AIToolCalls, AIRequests: s.AIRequests, AIResponses: s.AIResponses,
		Reporting: s.Reporting, ReportPackages: s.ReportPackages, Analytics: s.Analytics,
	}
}
