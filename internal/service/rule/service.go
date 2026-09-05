// Package rule bridges internal/ruleengine's self-contained rule
// validator/compiler/evaluator to persistence — the same "engine is
// self-contained, the service layer bridges it to the domain model and
// the database" split every prior phase's service package follows. It
// assembles internal/ruleengine.Event values entirely from data Phase
// 2/6/7/8/10 already persisted (findings, asset/endpoint observations,
// technology fingerprints, threat intelligence records — see events.go),
// evaluates a rule against them, and records the result through
// internal/repository/rule.
package rule

import (
	"context"
	"log/slog"

	"github.com/google/uuid"

	"ai-recon-platform/internal/database"
	domainrule "ai-recon-platform/internal/domain/rule"
	domaintarget "ai-recon-platform/internal/domain/target"
	apperrors "ai-recon-platform/internal/errors"
	endpointrepo "ai-recon-platform/internal/repository/endpoint"
	findingrepo "ai-recon-platform/internal/repository/finding"
	fingerprintrepo "ai-recon-platform/internal/repository/fingerprint"
	intelrepo "ai-recon-platform/internal/repository/intelligence"
	investigationrepo "ai-recon-platform/internal/repository/investigation"
	"ai-recon-platform/internal/repository/pagination"
	rulerepo "ai-recon-platform/internal/repository/rule"
	"ai-recon-platform/internal/ruleengine"
	assetsvc "ai-recon-platform/internal/service/asset"
	targetsvc "ai-recon-platform/internal/service/target"
)

// Service orchestrates every rule/detection/alert operation.
type Service struct {
	pool *database.Pool

	targets      *targetsvc.Service
	assets       *assetsvc.Service
	findings     findingrepo.Repository
	endpoints    endpointrepo.Repository
	fingerprints fingerprintrepo.Repository
	intelligence intelrepo.RecordRepository

	rules          rulerepo.Repository
	versions       rulerepo.VersionRepository
	matches        rulerepo.MatchRepository
	evidence       rulerepo.EvidenceRepository
	alerts         rulerepo.AlertRepository
	suppressions   rulerepo.SuppressionRepository
	investigations *investigationrepo.PostgresRepository

	engine *ruleengine.Engine
	cfg    ruleengine.Config
	logger *slog.Logger
}

// NewService builds a Service. targets/assets are Phase 2's services;
// findings/endpoints/fingerprints/intelligence/investigations are Phase
// 6/7/8/9/10's repositories, all reused directly (never duplicated —
// phase11.md's "do not duplicate existing functionality").
func NewService(pool *database.Pool, targets *targetsvc.Service, assets *assetsvc.Service, cfg ruleengine.Config, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	repo := rulerepo.NewPostgresRepository(pool)
	intelRepo := intelrepo.NewPostgresRepository(pool)
	return &Service{
		pool: pool, targets: targets, assets: assets,
		findings:     findingrepo.NewPostgresRepository(pool),
		endpoints:    endpointrepo.NewPostgresRepository(pool),
		fingerprints: fingerprintrepo.NewPostgresRepository(pool),
		intelligence: intelRepo,
		rules:        repo, versions: repo, matches: repo, evidence: repo, alerts: repo, suppressions: repo,
		investigations: investigationrepo.NewPostgresRepository(pool),
		engine:         ruleengine.NewEngine(), cfg: cfg, logger: logger,
	}
}

// CreateInput describes a new rule plus its first version (phase11.md
// §3/§4).
type CreateInput struct {
	TargetType  domaintarget.Type
	TargetValue string

	Name             string
	Description      string
	Category         string
	Tags             []string
	References       []string
	DocumentationURL string

	Definition        ruleengine.Definition
	ChangeDescription string

	CreatedBy string
}

// CreateRule validates and compiles the initial Definition, then
// persists the Rule (status draft) and its version 1 — a rule is never
// persisted with a Definition that failed to compile (phase11.md §71's
// "do not execute [or accept] an invalid definition" principle applied
// uniformly, not just to imports).
func (s *Service) CreateRule(ctx context.Context, input CreateInput) (domainrule.Rule, domainrule.Version, error) {
	if _, err := ruleengine.Compile(input.Definition); err != nil {
		return domainrule.Rule{}, domainrule.Version{}, apperrors.NewValidation("invalid rule definition", err)
	}

	target, err := s.targets.GetByValue(ctx, input.TargetType, input.TargetValue)
	if err != nil {
		return domainrule.Rule{}, domainrule.Version{}, err
	}

	r := domainrule.Rule{
		TargetID: target.ID, Name: input.Name, Description: input.Description,
		Status: domainrule.StatusDraft, RuleType: domainrule.Type(input.Definition.RuleType),
		Severity: domainrule.Severity(input.Definition.Severity), Confidence: domainrule.Confidence(input.Definition.Confidence),
		Category: input.Category, Tags: input.Tags, References: input.References, DocumentationURL: input.DocumentationURL,
		CreatedBy: input.CreatedBy,
	}
	if err := r.Validate(); err != nil {
		return domainrule.Rule{}, domainrule.Version{}, apperrors.NewValidation("invalid rule", err)
	}

	created, err := s.rules.CreateRule(ctx, r)
	if err != nil {
		return domainrule.Rule{}, domainrule.Version{}, err
	}

	version, err := s.createVersion(ctx, created.ID, input.Definition, input.ChangeDescription, input.CreatedBy)
	if err != nil {
		return domainrule.Rule{}, domainrule.Version{}, err
	}
	return created, version, nil
}

// createVersion validates+compiles def, persists it as the rule's next
// version, and syncs the rule's denormalized severity/confidence/type.
func (s *Service) createVersion(ctx context.Context, ruleID uuid.UUID, def ruleengine.Definition, changeDescription, createdBy string) (domainrule.Version, error) {
	compiled, err := ruleengine.Compile(def)
	if err != nil {
		return domainrule.Version{}, apperrors.NewValidation("invalid rule definition", err)
	}
	encoded, err := ruleengine.EncodeJSON(def)
	if err != nil {
		return domainrule.Version{}, err
	}

	v := domainrule.Version{
		RuleID: ruleID, Definition: string(encoded), DefinitionHash: compiled.Hash,
		Enabled: true, EventSchemaVersion: def.SchemaVersion, CreatedBy: createdBy, ChangeDescription: changeDescription,
	}
	if v.EventSchemaVersion < 1 {
		v.EventSchemaVersion = domainrule.DefaultEventSchemaVersion
	}
	if err := v.Validate(); err != nil {
		return domainrule.Version{}, apperrors.NewValidation("invalid rule version", err)
	}

	created, err := s.versions.CreateVersion(ctx, v)
	if err != nil {
		return domainrule.Version{}, err
	}

	if _, err := s.rules.SyncSeverityFromVersion(ctx, ruleID,
		domainrule.Severity(def.Severity), domainrule.Confidence(def.Confidence), domainrule.Type(def.RuleType)); err != nil {
		s.logger.Error("rule_severity_sync_failed", "rule_id", ruleID, "error", err)
	}
	return created, nil
}

// CreateVersion adds a new version to an existing rule (phase11.md §4) —
// the only way to change a rule's logic; the previous version's
// Definition is never touched (phase11.md §5).
func (s *Service) CreateVersion(ctx context.Context, ruleID uuid.UUID, def ruleengine.Definition, changeDescription, createdBy string) (domainrule.Version, error) {
	if _, err := s.rules.GetRuleByID(ctx, ruleID); err != nil {
		return domainrule.Version{}, err
	}
	return s.createVersion(ctx, ruleID, def, changeDescription, createdBy)
}

// ResolveTarget loads the target for (targetType, targetValue) — the
// same convention every other phase's service uses.
func (s *Service) ResolveTarget(ctx context.Context, targetType domaintarget.Type, targetValue string) (domaintarget.Target, error) {
	return s.targets.GetByValue(ctx, targetType, targetValue)
}

// GetRule returns a rule by id.
func (s *Service) GetRule(ctx context.Context, id uuid.UUID) (domainrule.Rule, error) {
	return s.rules.GetRuleByID(ctx, id)
}

// GetRuleByName returns a rule by its (target, name) identity.
func (s *Service) GetRuleByName(ctx context.Context, targetID uuid.UUID, name string) (domainrule.Rule, error) {
	return s.rules.GetByName(ctx, targetID, name)
}

// ListRules returns a page of rules matching filter.
func (s *Service) ListRules(ctx context.Context, filter rulerepo.ListFilter) (pagination.Page[domainrule.Rule], error) {
	return s.rules.ListRules(ctx, filter)
}

// ListVersions returns every version of ruleID, oldest first.
func (s *Service) ListVersions(ctx context.Context, ruleID uuid.UUID) ([]domainrule.Version, error) {
	return s.versions.ListVersions(ctx, ruleID)
}

// GetVersion returns one specific version.
func (s *Service) GetVersion(ctx context.Context, ruleID uuid.UUID, version int) (domainrule.Version, error) {
	return s.versions.GetByRuleAndVersion(ctx, ruleID, version)
}

// Enable transitions a rule to StatusEnabled (phase11.md §31) — no new
// matches are produced until this happens.
func (s *Service) Enable(ctx context.Context, ruleID uuid.UUID, actorID string) (domainrule.Rule, error) {
	return s.rules.UpdateRuleStatus(ctx, ruleID, domainrule.StatusEnabled, actorID)
}

// Disable transitions a rule to StatusDisabled — historical matches
// remain available (phase11.md §31).
func (s *Service) Disable(ctx context.Context, ruleID uuid.UUID, actorID string) (domainrule.Rule, error) {
	return s.rules.UpdateRuleStatus(ctx, ruleID, domainrule.StatusDisabled, actorID)
}

// Deprecate transitions a rule to StatusDeprecated (phase11.md §30) — it
// remains available historically, never deleted.
func (s *Service) Deprecate(ctx context.Context, ruleID uuid.UUID, actorID string) (domainrule.Rule, error) {
	return s.rules.UpdateRuleStatus(ctx, ruleID, domainrule.StatusDeprecated, actorID)
}

// SetVersionEnabled toggles one version's own Enabled flag, independent
// of the rule's overall Status.
func (s *Service) SetVersionEnabled(ctx context.Context, versionID uuid.UUID, enabled bool) (domainrule.Version, error) {
	return s.versions.SetEnabled(ctx, versionID, enabled)
}
