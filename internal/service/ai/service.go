package ai

import (
	"context"
	"log/slog"
	"time"

	"ai-surface-platform/internal/ai"
	"ai-surface-platform/internal/ai/tools"
	"ai-surface-platform/internal/database"
	domaintarget "ai-surface-platform/internal/domain/target"
	airepo "ai-surface-platform/internal/repository/ai"
	assetrepo "ai-surface-platform/internal/repository/asset"
	correlationrepo "ai-surface-platform/internal/repository/correlation"
	findingrepo "ai-surface-platform/internal/repository/finding"
	intelrepo "ai-surface-platform/internal/repository/intelligence"
	investigationrepo "ai-surface-platform/internal/repository/investigation"
	rulerepo "ai-surface-platform/internal/repository/rule"
	targetsvc "ai-surface-platform/internal/service/target"
)

// Config configures Service — every field has a safe, explicit default
// applied by NewService when zero (phase13.md §85: "use safe defaults").
type Config struct {
	// RequestTimeout bounds one end-to-end AI task (phase13.md §56).
	RequestTimeout time.Duration
	// ToolTimeout bounds one individual tool call (phase13.md §33/§56).
	ToolTimeout time.Duration
	// MaxRetries/RetryBackoff bound provider retry behavior (phase13.md
	// §57) — see internal/ai.WithRetries.
	MaxRetries   int
	RetryBackoff time.Duration

	Limits ai.Limits

	// DefaultProvider names which registered internal/ai.Provider to use
	// when a caller doesn't specify one — "mock" unless an operator
	// explicitly configures a real provider (phase13.md §85/§88).
	DefaultProvider string

	RateLimit RateLimitConfig
}

// Effective returns c with every zero field replaced by its default.
func (c Config) Effective() Config {
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 30 * time.Second
	}
	if c.ToolTimeout <= 0 {
		c.ToolTimeout = 5 * time.Second
	}
	if c.RetryBackoff <= 0 {
		c.RetryBackoff = 500 * time.Millisecond
	}
	if c.DefaultProvider == "" {
		c.DefaultProvider = "mock"
	}
	return c
}

// Service orchestrates every AI-assistant operation — the bridge between
// internal/ai's self-contained engine and Phase 2/7/8/9/10/11/12's own
// repositories, exactly the split internal/service/correlation follows
// for Phase 12.
type Service struct {
	pool *database.Pool

	targets *targetsvc.Service

	investigations investigationrepo.Repository
	evidence       investigationrepo.EvidenceRepository
	timeline       investigationrepo.TimelineRepository
	notes          investigationrepo.NoteRepository

	findings findingrepo.Repository
	assets   assetrepo.Repository

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

	sessions  airepo.SessionRepository
	messages  airepo.MessageRepository
	requests  airepo.RequestRepository
	responses airepo.ResponseRepository
	toolCalls airepo.ToolCallRepository

	providers *ai.ProviderRegistry
	toolReg   *ai.ToolRegistry
	executor  *ai.Executor
	assistant *ai.Assistant

	limiter *rateLimiter

	cfg    Config
	logger *slog.Logger
}

// NewService builds a Service. Every repository parameter is reused
// directly from its owning phase (never duplicated — phase13.md's own
// "reuse existing systems" instruction, §1). providers should already
// have every configured internal/ai.Provider registered (at minimum
// "mock" — see cmd/cli/commands/ai.go's buildAIService).
func NewService(
	pool *database.Pool, targets *targetsvc.Service,
	investigations investigationrepo.Repository, evidence investigationrepo.EvidenceRepository,
	timeline investigationrepo.TimelineRepository, notes investigationrepo.NoteRepository,
	findings findingrepo.Repository, assets assetrepo.Repository,
	rules rulerepo.Repository, matches rulerepo.MatchRepository, alerts rulerepo.AlertRepository,
	correlations correlationrepo.Repository, nodes correlationrepo.NodeRepository, edges correlationrepo.EdgeRepository,
	chains correlationrepo.ChainRepository, stages correlationrepo.StageRepository,
	intelRecords intelrepo.RecordRepository, risk intelrepo.RiskRepository,
	sessions airepo.SessionRepository, messages airepo.MessageRepository,
	requests airepo.RequestRepository, responses airepo.ResponseRepository, toolCalls airepo.ToolCallRepository,
	providers *ai.ProviderRegistry, cfg Config, logger *slog.Logger,
) *Service {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	cfg = cfg.Effective()

	s := &Service{
		pool: pool, targets: targets,
		investigations: investigations, evidence: evidence, timeline: timeline, notes: notes,
		findings: findings, assets: assets,
		rules: rules, matches: matches, alerts: alerts,
		correlations: correlations, nodes: nodes, edges: edges, chains: chains, stages: stages,
		intelRecords: intelRecords, risk: risk,
		sessions: sessions, messages: messages, requests: requests, responses: responses, toolCalls: toolCalls,
		providers: providers, cfg: cfg, logger: logger,
		limiter: newRateLimiter(cfg.RateLimit),
	}

	s.toolReg = ai.NewToolRegistry()
	if err := tools.RegisterAll(s.toolReg, dataSource{svc: s}); err != nil {
		logger.Error("ai_tool_registration_failed", "error", err)
	}
	s.executor = ai.NewExecutor(s.toolReg, s.auditToolCall, cfg.ToolTimeout)
	s.assistant = &ai.Assistant{MaxOutputTokens: 2000, Temperature: 0.2}

	return s
}

// ResolveTarget loads the target for (targetType, targetValue) — the
// same convention every other phase's service uses.
func (s *Service) ResolveTarget(ctx context.Context, targetType domaintarget.Type, targetValue string) (domaintarget.Target, error) {
	return s.targets.GetByValue(ctx, targetType, targetValue)
}

// provider resolves name (or cfg.DefaultProvider if empty) against the
// registry, wrapped with bounded retries (phase13.md §57).
func (s *Service) provider(name string) (ai.Provider, error) {
	if name == "" {
		name = s.cfg.DefaultProvider
	}
	p, err := s.providers.Get(name)
	if err != nil {
		return nil, err
	}
	return ai.WithRetries(p, s.cfg.MaxRetries, s.cfg.RetryBackoff), nil
}
