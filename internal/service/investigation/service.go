// Package investigation bridges internal/investigation's self-contained
// correlation engine to persistence and orchestrates every other
// analyst-facing operation (case management, evidence attachment,
// timeline, hypotheses, notes, clusters, export) — the same "engine is
// self-contained, the service layer bridges it to the domain model and
// the database" split every prior phase's service package follows.
package investigation

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/database"
	domaininvestigation "ai-recon-platform/internal/domain/investigation"
	domaintarget "ai-recon-platform/internal/domain/target"
	apperrors "ai-recon-platform/internal/errors"
	"ai-recon-platform/internal/investigation"
	endpointrepo "ai-recon-platform/internal/repository/endpoint"
	findingrepo "ai-recon-platform/internal/repository/finding"
	fingerprintrepo "ai-recon-platform/internal/repository/fingerprint"
	investigationrepo "ai-recon-platform/internal/repository/investigation"
	"ai-recon-platform/internal/repository/pagination"
	assetsvc "ai-recon-platform/internal/service/asset"
	targetsvc "ai-recon-platform/internal/service/target"
)

// Service orchestrates every investigation operation.
type Service struct {
	pool *database.Pool

	targets       *targetsvc.Service
	assets        *assetsvc.Service
	endpoints     endpointrepo.Repository
	findings      findingrepo.Repository
	findingEvents findingrepo.EventRepository
	fingerprints  fingerprintrepo.Repository

	investigations investigationrepo.Repository
	evidence       investigationrepo.EvidenceRepository
	timeline       investigationrepo.TimelineRepository
	relationships  investigationrepo.RelationshipRepository
	hypotheses     investigationrepo.HypothesisRepository
	notes          investigationrepo.NoteRepository
	clusters       investigationrepo.ClusterRepository

	registry *investigation.Registry
	engine   *investigation.Engine
	logger   *slog.Logger
}

// NewService builds a Service. targets/assets are Phase 2's services;
// endpoints/findings/fingerprints are Phase 6/7/8's repositories, all
// reused directly (never duplicated — phase9.md §1) exactly the way
// internal/service/detection reuses fingerprintrepo.Repository directly.
// registry must already have every correlation rule this deployment
// wants registered (see internal/investigation/correlation.RegisterAll).
func NewService(pool *database.Pool, targets *targetsvc.Service, assets *assetsvc.Service, registry *investigation.Registry, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	repo := investigationrepo.NewPostgresRepository(pool)
	findingRepo := findingrepo.NewPostgresRepository(pool)
	return &Service{
		pool: pool, targets: targets, assets: assets,
		endpoints: endpointrepo.NewPostgresRepository(pool), findings: findingRepo, findingEvents: findingRepo,
		fingerprints:   fingerprintrepo.NewPostgresRepository(pool),
		investigations: repo, evidence: repo, timeline: repo, relationships: repo,
		hypotheses: repo, notes: repo, clusters: repo,
		registry: registry, engine: investigation.NewEngine(registry), logger: logger,
	}
}

// CreateInput describes a new investigation (phase9.md §2/§57).
type CreateInput struct {
	TargetType  domaintarget.Type
	TargetValue string
	Title       string
	Description string
	Priority    domaininvestigation.Priority
	Severity    domaininvestigation.Severity
	CreatedBy   string
	AssignedTo  string
	// FindingID/AssetID, if set, are attached immediately after creation
	// (phase9.md §57's "--finding <finding-id> / --asset <asset-id>").
	FindingID *uuid.UUID
	AssetID   *uuid.UUID
}

// Create validates and persists a new Investigation, recording its
// creation on its own timeline, then attaches an initial finding/asset if
// requested.
func (s *Service) Create(ctx context.Context, input CreateInput) (domaininvestigation.Investigation, error) {
	target, err := s.targets.GetByValue(ctx, input.TargetType, input.TargetValue)
	if err != nil {
		return domaininvestigation.Investigation{}, fmt.Errorf("loading target: %w", err)
	}

	inv := domaininvestigation.Investigation{
		TargetID: target.ID, Title: input.Title, Description: input.Description,
		Status: domaininvestigation.StatusNew, Priority: input.Priority, Severity: input.Severity,
		CreatedBy: input.CreatedBy, AssignedTo: input.AssignedTo,
	}
	if err := inv.Validate(); err != nil {
		return domaininvestigation.Investigation{}, apperrors.NewValidation("invalid investigation", err)
	}

	created, err := s.investigations.Create(ctx, inv)
	if err != nil {
		return domaininvestigation.Investigation{}, err
	}

	s.recordEvent(ctx, created, domaininvestigation.EventInvestigationCreated, created.Title+" was opened.", "", input.CreatedBy, nil)

	if input.FindingID != nil {
		if _, err := s.AttachFinding(ctx, created.ID, *input.FindingID, domaininvestigation.RelationRelated, input.CreatedBy); err != nil {
			s.logger.Error("investigation_initial_finding_attach_failed", "investigation_id", created.ID, "finding_id", *input.FindingID, "error", err)
		}
	}
	if input.AssetID != nil {
		if _, err := s.AttachEvidence(ctx, created.ID, domaininvestigation.EntityAsset, *input.AssetID, input.CreatedBy); err != nil {
			s.logger.Error("investigation_initial_asset_attach_failed", "investigation_id", created.ID, "asset_id", *input.AssetID, "error", err)
		}
	}

	return s.GetByID(ctx, created.ID)
}

// GetByID returns the investigation with the given id.
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (domaininvestigation.Investigation, error) {
	return s.investigations.GetByID(ctx, id)
}

// List returns a page of investigations matching filter.
func (s *Service) List(ctx context.Context, filter investigationrepo.ListFilter) (pagination.Page[domaininvestigation.Investigation], error) {
	return s.investigations.List(ctx, filter)
}

// UpdateInput describes a mutable-field update (phase9.md §8). Empty
// string fields are left unchanged; use explicit Clear* flags to blank a
// field.
type UpdateInput struct {
	Title       *string
	Description *string
	Status      *domaininvestigation.Status
	Priority    *domaininvestigation.Priority
	Severity    *domaininvestigation.Severity
	AssignedTo  *string
	ActorID     string
}

// Update applies input to the investigation, using optimistic concurrency
// (expectedVersion — phase9.md §74) and recording one timeline event per
// changed field.
func (s *Service) Update(ctx context.Context, id uuid.UUID, input UpdateInput, expectedVersion int) (domaininvestigation.Investigation, error) {
	current, err := s.investigations.GetByID(ctx, id)
	if err != nil {
		return domaininvestigation.Investigation{}, err
	}

	next := current
	if input.Title != nil {
		next.Title = *input.Title
	}
	if input.Description != nil {
		next.Description = *input.Description
	}
	if input.Status != nil {
		next.Status = *input.Status
	}
	if input.Priority != nil {
		next.Priority = *input.Priority
	}
	if input.Severity != nil {
		next.Severity = *input.Severity
	}
	if input.AssignedTo != nil {
		next.AssignedTo = *input.AssignedTo
	}
	if err := next.Validate(); err != nil {
		return domaininvestigation.Investigation{}, apperrors.NewValidation("invalid investigation update", err)
	}

	updated, err := s.investigations.Update(ctx, next, expectedVersion)
	if err != nil {
		return domaininvestigation.Investigation{}, err
	}

	if input.Severity != nil && *input.Severity != current.Severity {
		s.recordEvent(ctx, updated, domaininvestigation.EventSeverityChanged,
			fmt.Sprintf("Severity changed from %q to %q.", current.Severity, updated.Severity), "", input.ActorID, nil)
	}
	if input.Priority != nil && *input.Priority != current.Priority {
		s.recordEvent(ctx, updated, domaininvestigation.EventPriorityChanged,
			fmt.Sprintf("Priority changed from %q to %q.", current.Priority, updated.Priority), "", input.ActorID, nil)
	}
	if input.AssignedTo != nil && *input.AssignedTo != current.AssignedTo {
		s.recordEvent(ctx, updated, domaininvestigation.EventAssignmentChanged,
			fmt.Sprintf("Assigned to %q.", updated.AssignedTo), "", input.ActorID, nil)
	}
	if input.Status != nil && *input.Status != current.Status {
		s.recordEvent(ctx, updated, domaininvestigation.EventStatusChanged,
			fmt.Sprintf("Status changed from %q to %q.", current.Status, updated.Status), "", input.ActorID, nil)
	}

	return updated, nil
}

// Close transitions an investigation to closed (phase9.md §8's "close
// investigation"). reason is optional but recorded when given.
func (s *Service) Close(ctx context.Context, id uuid.UUID, expectedVersion int, actorID, reason string) (domaininvestigation.Investigation, error) {
	status := domaininvestigation.StatusClosed
	updated, err := s.Update(ctx, id, UpdateInput{Status: &status, ActorID: actorID}, expectedVersion)
	if err != nil {
		return domaininvestigation.Investigation{}, err
	}
	s.recordEvent(ctx, updated, domaininvestigation.EventIncidentClosed, "Investigation closed.", reason, actorID, nil)
	return updated, nil
}

// Reopen transitions a closed investigation back to open (phase9.md §31
// — never silent, reason is required and always recorded).
func (s *Service) Reopen(ctx context.Context, id uuid.UUID, expectedVersion int, actorID, reason string) (domaininvestigation.Investigation, error) {
	if strings.TrimSpace(reason) == "" {
		return domaininvestigation.Investigation{}, apperrors.NewValidation("a reason is required to reopen an investigation", nil)
	}
	current, err := s.investigations.GetByID(ctx, id)
	if err != nil {
		return domaininvestigation.Investigation{}, err
	}
	if !current.Status.Terminal() {
		return domaininvestigation.Investigation{}, apperrors.NewValidation("investigation is not closed", nil)
	}

	status := domaininvestigation.StatusOpen
	updated, err := s.Update(ctx, id, UpdateInput{Status: &status, ActorID: actorID}, expectedVersion)
	if err != nil {
		return domaininvestigation.Investigation{}, err
	}
	s.recordEvent(ctx, updated, domaininvestigation.EventInvestigationReopened, "Investigation reopened: "+reason, reason, actorID, nil)
	return updated, nil
}

// widenObservedWindow extends inv's FirstObservedAt/LastObservedAt to
// include observedAt — called whenever new evidence is attached
// (phase9.md §3's incident-facing timestamps, always derived from real
// evidence, never fabricated).
func (s *Service) widenObservedWindow(ctx context.Context, investigationID uuid.UUID, observedAt time.Time) {
	if observedAt.IsZero() {
		return
	}
	if _, err := s.investigations.UpdateFirstLastObserved(ctx, investigationID, observedAt); err != nil {
		s.logger.Error("investigation_observed_window_update_failed", "investigation_id", investigationID, "error", err)
	}
}
