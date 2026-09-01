// Package target implements persistence for the target domain model.
package target

import (
	"context"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/target"
	"ai-recon-platform/internal/repository/pagination"
)

// ListFilter narrows a target listing. Zero-valued fields are not applied.
type ListFilter struct {
	Type                target.Type
	AuthorizationStatus target.AuthorizationStatus
	Pagination          pagination.Params
}

// Repository persists and queries Target rows. Implementations must accept
// context, return the platform's typed errors (see internal/errors), use
// parameterized queries exclusively, and never leak SQL or driver details
// to callers.
type Repository interface {
	// Create inserts a new target and returns it with server-assigned
	// fields (ID, CreatedAt, UpdatedAt) populated.
	Create(ctx context.Context, t target.Target) (target.Target, error)
	// GetByID returns the target with the given id, or a
	// errors.CategoryNotFound error if none exists.
	GetByID(ctx context.Context, id uuid.UUID) (target.Target, error)
	// GetByValue returns the target with the given (type, value) pair —
	// the deterministic duplicate-detection key — or a
	// errors.CategoryNotFound error if none exists.
	GetByValue(ctx context.Context, typ target.Type, value string) (target.Target, error)
	// List returns a page of targets matching filter, ordered by
	// (created_at, id).
	List(ctx context.Context, filter ListFilter) (pagination.Page[target.Target], error)
	// Update persists changes to an existing target's mutable fields
	// (name, description, authorization status) and refreshes UpdatedAt.
	Update(ctx context.Context, t target.Target) (target.Target, error)
}
