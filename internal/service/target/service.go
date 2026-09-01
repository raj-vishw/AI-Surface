// Package target implements the business logic sitting between callers
// (the CLI, future discovery modules, the future API) and
// internal/repository/target's persistence.
package target

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"

	"ai-recon-platform/internal/database"
	domaintarget "ai-recon-platform/internal/domain/target"
	apperrors "ai-recon-platform/internal/errors"
	"ai-recon-platform/internal/repository/pagination"
	targetrepo "ai-recon-platform/internal/repository/target"
)

// Service implements target business logic: validation, duplicate
// detection, and the authorization-state boundary future scanning phases
// depend on.
type Service struct {
	pool *database.Pool
	repo targetrepo.Repository
}

// NewService builds a Service backed by pool.
func NewService(pool *database.Pool) *Service {
	return &Service{pool: pool, repo: targetrepo.NewPostgresRepository(pool)}
}

// CreateInput is the input to Create.
type CreateInput struct {
	Name        string
	Type        domaintarget.Type
	Value       string
	Description string
}

// Create validates input, rejects an exact (type, value) duplicate, and
// persists a new target with AuthorizationStatus UNVERIFIED — a target is
// never created pre-authorized; see UpdateAuthorizationStatus.
func (s *Service) Create(ctx context.Context, input CreateInput) (domaintarget.Target, error) {
	t := domaintarget.Target{
		Name:                strings.TrimSpace(input.Name),
		Type:                input.Type,
		Value:               strings.TrimSpace(input.Value),
		Description:         input.Description,
		AuthorizationStatus: domaintarget.AuthorizationUnverified,
	}

	if err := t.Validate(); err != nil {
		return domaintarget.Target{}, apperrors.NewValidation("invalid target", err)
	}

	if _, err := s.repo.GetByValue(ctx, t.Type, t.Value); err == nil {
		return domaintarget.Target{}, apperrors.NewConflict("a target with this type and value already exists", nil)
	} else if !isNotFound(err) {
		return domaintarget.Target{}, err
	}

	return s.repo.Create(ctx, t)
}

// GetByID returns the target with the given id.
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (domaintarget.Target, error) {
	return s.repo.GetByID(ctx, id)
}

// GetByValue returns the target matching the given (type, value) pair.
func (s *Service) GetByValue(ctx context.Context, typ domaintarget.Type, value string) (domaintarget.Target, error) {
	return s.repo.GetByValue(ctx, typ, strings.TrimSpace(value))
}

// List returns a page of targets matching filter.
func (s *Service) List(ctx context.Context, filter targetrepo.ListFilter) (pagination.Page[domaintarget.Target], error) {
	return s.repo.List(ctx, filter)
}

// UpdateAuthorizationStatus explicitly transitions a target's authorization
// state. This is the only supported way a target becomes AUTHORIZED — the
// system must never infer authorization from a target merely existing.
func (s *Service) UpdateAuthorizationStatus(ctx context.Context, id uuid.UUID, status domaintarget.AuthorizationStatus) (domaintarget.Target, error) {
	if !status.Valid() {
		return domaintarget.Target{}, apperrors.NewValidation("invalid authorization status", nil)
	}

	t, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return domaintarget.Target{}, err
	}
	t.AuthorizationStatus = status

	return s.repo.Update(ctx, t)
}

// IsAuthorized reports whether id currently permits active operations.
// Future scanning phases must call this (or check
// domaintarget.Target.IsAuthorized directly on an already-fetched Target)
// before doing anything active — it is the platform's authorization
// boundary; see SECURITY.md.
func (s *Service) IsAuthorized(ctx context.Context, id uuid.UUID) (bool, error) {
	t, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return false, err
	}
	return t.IsAuthorized(), nil
}

func isNotFound(err error) bool {
	var appErr *apperrors.Error
	return errors.As(err, &appErr) && appErr.Category == apperrors.CategoryNotFound
}
