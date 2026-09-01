// Package endpoint implements persistence for the endpoint domain model.
package endpoint

import (
	"context"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/endpoint"
	"ai-recon-platform/internal/repository/pagination"
)

// ListFilter narrows an endpoint listing. Zero-valued fields are not
// applied.
type ListFilter struct {
	AssetID    uuid.UUID
	Status     endpoint.Status
	Pagination pagination.Params
}

// Repository persists and queries Endpoint rows.
type Repository interface {
	// Upsert inserts e's row if no endpoint with its (AssetID, Method,
	// normalized URL) exists yet, or merges a new observation into the
	// existing row if one does: LastSeen advances to the later of the two
	// timestamps, FirstSeen moves to the earlier of the two (so it always
	// ends up as the true earliest observation regardless of the order
	// concurrent callers' upserts happen to reach the database in —
	// see asset.Repository.Upsert's doc comment for why "earlier" rather
	// than "never touched" is the correct rule here), ContentType/
	// StatusCode/ResponseHash/QueryPattern update to the latest
	// observation, and Metadata is shallow-merged. Status is preserved —
	// the same explicit-status-change discipline as asset.Repository.
	// created reports whether a new row was inserted.
	Upsert(ctx context.Context, e endpoint.Endpoint) (result endpoint.Endpoint, created bool, err error)
	// GetByID returns the endpoint with the given id, or a
	// errors.CategoryNotFound error if none exists.
	GetByID(ctx context.Context, id uuid.UUID) (endpoint.Endpoint, error)
	// ListByAsset returns a page of endpoints for filter.AssetID, ordered
	// by (created_at, id).
	ListByAsset(ctx context.Context, filter ListFilter) (pagination.Page[endpoint.Endpoint], error)
}
