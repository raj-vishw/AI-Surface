// Package asset implements the business logic sitting between callers (the
// CLI, future discovery modules, the future API) and
// internal/repository/asset's and internal/repository/endpoint's
// persistence: validation, identity computation, metadata redaction, and
// the transactional "record an observation" operation.
package asset

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"ai-recon-platform/internal/database"
	domainasset "ai-recon-platform/internal/domain/asset"
	domainendpoint "ai-recon-platform/internal/domain/endpoint"
	apperrors "ai-recon-platform/internal/errors"
	assetrepo "ai-recon-platform/internal/repository/asset"
	endpointrepo "ai-recon-platform/internal/repository/endpoint"
	"ai-recon-platform/internal/repository/pagination"
)

// Service implements asset business logic.
type Service struct {
	pool      *database.Pool
	assets    assetrepo.Repository
	evidence  assetrepo.EvidenceRepository
	endpoints endpointrepo.Repository
}

// NewService builds a Service backed by pool.
func NewService(pool *database.Pool) *Service {
	repo := assetrepo.NewPostgresRepository(pool)
	return &Service{
		pool:      pool,
		assets:    repo,
		evidence:  repo,
		endpoints: endpointrepo.NewPostgresRepository(pool),
	}
}

// Input is the caller-supplied description of an observed asset,
// before identity computation, metadata sanitization, or default filling.
type Input struct {
	TargetID       uuid.UUID
	OrganizationID *uuid.UUID
	Type           domainasset.Type
	Hostname       *string
	IP             *string
	Port           *int
	Protocol       *string
	URL            *string
	Technology     *string
	Provider       *string
	Model          *string
	Environment    *string
	Source         string
	Confidence     domainasset.Confidence
	Metadata       map[string]any
	ObservedAt     time.Time // defaults to now if zero
}

func (input Input) toDomain() domainasset.Asset {
	observedAt := input.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	return domainasset.Asset{
		TargetID:       input.TargetID,
		OrganizationID: input.OrganizationID,
		Type:           input.Type,
		Hostname:       input.Hostname,
		IP:             input.IP,
		Port:           input.Port,
		Protocol:       input.Protocol,
		URL:            input.URL,
		Technology:     input.Technology,
		Provider:       input.Provider,
		Model:          input.Model,
		Environment:    input.Environment,
		Source:         input.Source,
		Confidence:     input.Confidence,
		Metadata:       domainasset.SanitizeMetadata(input.Metadata),
		FirstSeen:      observedAt,
		LastSeen:       observedAt,
	}
}

// prepare validates input, sanitizes its metadata, and computes its
// identity key — the three steps every write path shares.
func prepare(input Input) (domainasset.Asset, error) {
	a := input.toDomain()
	if err := a.Validate(); err != nil {
		return domainasset.Asset{}, apperrors.NewValidation("invalid asset", err)
	}
	identityKey, err := domainasset.IdentityKey(a)
	if err != nil {
		return domainasset.Asset{}, apperrors.NewValidation("computing asset identity", err)
	}
	a.IdentityKey = identityKey
	return a, nil
}

// UpsertAsset validates, sanitizes, and persists an observed asset,
// creating it if this is the first observation of its identity within its
// target or merging into the existing row otherwise (see
// internal/repository/asset.Repository.Upsert for the exact merge rules).
// It does not record evidence — use RecordObservation for the common case
// of "upsert the asset and remember why we believe it exists" atomically.
func (s *Service) UpsertAsset(ctx context.Context, input Input) (domainasset.Asset, bool, error) {
	a, err := prepare(input)
	if err != nil {
		return domainasset.Asset{}, false, err
	}
	return s.assets.Upsert(ctx, a)
}

// ObservationInput extends Input with the evidence that justifies this
// observation. RecordObservation persists both atomically.
type ObservationInput struct {
	Asset        Input
	EvidenceType domainasset.EvidenceType
	EvidenceData map[string]any
}

// RecordObservation upserts the asset described by input.Asset and records
// input's evidence in a single database transaction: if either write
// fails, neither is applied, so the asset inventory never ends up with an
// asset row that claims evidence which was never actually stored (see
// phase2.md §28).
func (s *Service) RecordObservation(ctx context.Context, input ObservationInput) (domainasset.Asset, domainasset.Evidence, error) {
	a, err := prepare(input.Asset)
	if err != nil {
		return domainasset.Asset{}, domainasset.Evidence{}, err
	}

	ev := domainasset.Evidence{
		Source:       a.Source,
		EvidenceType: input.EvidenceType,
		EvidenceData: domainasset.SanitizeMetadata(input.EvidenceData),
		Confidence:   a.Confidence,
		ObservedAt:   a.FirstSeen,
	}
	// ev.AssetID isn't known until the asset upsert below assigns it, so
	// full validation (which requires a non-empty AssetID) happens inside
	// the transaction, right after that assignment — not here.

	var (
		upserted domainasset.Asset
		recorded domainasset.Evidence
	)
	err = s.pool.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		txRepo := assetrepo.NewPostgresRepository(tx)

		result, _, upsertErr := txRepo.Upsert(ctx, a)
		if upsertErr != nil {
			return upsertErr
		}
		upserted = result

		ev.AssetID = upserted.ID
		if err := ev.Validate(); err != nil {
			return apperrors.NewValidation("invalid evidence", err)
		}

		evResult, _, evidenceErr := txRepo.CreateEvidence(ctx, ev)
		if evidenceErr != nil {
			return evidenceErr
		}
		recorded = evResult
		return nil
	})
	if err != nil {
		return domainasset.Asset{}, domainasset.Evidence{}, err
	}

	return upserted, recorded, nil
}

// GetByID returns the asset with the given id.
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (domainasset.Asset, error) {
	return s.assets.GetByID(ctx, id)
}

// GetByIdentity returns the asset within targetID whose identity matches
// the asset described by input (computed the same way Upsert would).
func (s *Service) GetByIdentity(ctx context.Context, input Input) (domainasset.Asset, error) {
	a := input.toDomain()
	identityKey, err := domainasset.IdentityKey(a)
	if err != nil {
		return domainasset.Asset{}, apperrors.NewValidation("computing asset identity", err)
	}
	return s.assets.GetByIdentity(ctx, input.TargetID, identityKey)
}

// List returns a page of assets matching filter.
func (s *Service) List(ctx context.Context, filter assetrepo.ListFilter) (pagination.Page[domainasset.Asset], error) {
	return s.assets.List(ctx, filter)
}

// UpdateStatus explicitly changes an asset's lifecycle status.
func (s *Service) UpdateStatus(ctx context.Context, id uuid.UUID, status domainasset.Status) (domainasset.Asset, error) {
	if !status.Valid() {
		return domainasset.Asset{}, apperrors.NewValidation("invalid asset status", nil)
	}
	return s.assets.UpdateStatus(ctx, id, status)
}

// Retire marks an asset RETIRED (a soft delete — see phase2.md §34).
func (s *Service) Retire(ctx context.Context, id uuid.UUID) (domainasset.Asset, error) {
	return s.assets.Retire(ctx, id)
}

// ListEvidence returns a page of evidence for an asset.
func (s *Service) ListEvidence(ctx context.Context, filter assetrepo.EvidenceListFilter) (pagination.Page[domainasset.Evidence], error) {
	return s.evidence.ListEvidenceByAsset(ctx, filter)
}

// EndpointInput is the caller-supplied description of an observed
// endpoint, before URL normalization.
type EndpointInput struct {
	AssetID      uuid.UUID
	URL          string
	Method       domainendpoint.Method
	ContentType  string
	StatusCode   *int
	ResponseHash string
	Metadata     map[string]any
	ObservedAt   time.Time
}

// UpsertEndpoint normalizes input.URL and persists the resulting endpoint,
// creating it if this is the first observation of its (asset, method,
// normalized URL) or merging into the existing row otherwise.
func (s *Service) UpsertEndpoint(ctx context.Context, input EndpointInput) (domainendpoint.Endpoint, bool, error) {
	norm, err := domainendpoint.Normalize(input.URL)
	if err != nil {
		return domainendpoint.Endpoint{}, false, apperrors.NewValidation("invalid endpoint URL", err)
	}

	observedAt := input.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}

	e := domainendpoint.Endpoint{
		AssetID:      input.AssetID,
		URL:          norm.URL,
		Method:       input.Method,
		Scheme:       norm.Scheme,
		Host:         norm.Host,
		Port:         norm.Port,
		Path:         norm.Path,
		QueryPattern: norm.QueryPattern,
		ContentType:  input.ContentType,
		StatusCode:   input.StatusCode,
		ResponseHash: input.ResponseHash,
		Metadata:     domainasset.SanitizeMetadata(input.Metadata),
		FirstSeen:    observedAt,
		LastSeen:     observedAt,
	}
	if err := e.Validate(); err != nil {
		return domainendpoint.Endpoint{}, false, apperrors.NewValidation("invalid endpoint", err)
	}

	return s.endpoints.Upsert(ctx, e)
}

// ListEndpoints returns a page of endpoints for an asset.
func (s *Service) ListEndpoints(ctx context.Context, filter endpointrepo.ListFilter) (pagination.Page[domainendpoint.Endpoint], error) {
	return s.endpoints.ListByAsset(ctx, filter)
}
