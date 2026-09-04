// Package asset implements the business logic sitting between callers (the
// CLI, future discovery modules, the future API) and
// internal/repository/asset's and internal/repository/endpoint's
// persistence: validation, identity computation, metadata redaction, and
// the transactional "record an observation" operation.
package asset

import (
	"context"
	"fmt"
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
	pool             *database.Pool
	assets           assetrepo.Repository
	evidence         assetrepo.EvidenceRepository
	endpoints        endpointrepo.Repository
	endpointParams   endpointrepo.ParameterRepository
	endpointEvidence endpointrepo.EvidenceRepository
}

// NewService builds a Service backed by pool.
func NewService(pool *database.Pool) *Service {
	repo := assetrepo.NewPostgresRepository(pool)
	endpointRepo := endpointrepo.NewPostgresRepository(pool)
	return &Service{
		pool:             pool,
		assets:           repo,
		evidence:         repo,
		endpoints:        endpointRepo,
		endpointParams:   endpointRepo,
		endpointEvidence: endpointRepo,
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
// endpoint, before URL normalization. The Phase 7 fields
// (Classification/APIType/APIVersion/Sources/Confidence/Documented/
// Observed/Inferred/ScanID/ContentLength) are all optional — Phase 3's
// callers leave them zero-valued, exactly as before this extension.
type EndpointInput struct {
	AssetID       uuid.UUID
	ScanID        *uuid.UUID
	URL           string
	Method        domainendpoint.Method
	ContentType   string
	ContentLength *int64
	StatusCode    *int
	ResponseHash  string

	Classification domainendpoint.Classification
	APIType        string
	APIVersion     string
	Sources        []string
	Confidence     float64
	Documented     bool
	Observed       bool
	Inferred       bool

	Metadata   map[string]any
	ObservedAt time.Time
}

// toDomain normalizes input.URL and builds the domain Endpoint it
// describes — the shared step UpsertEndpoint and
// RecordEndpointObservation both need.
func (input EndpointInput) toDomain() (domainendpoint.Endpoint, error) {
	norm, err := domainendpoint.Normalize(input.URL)
	if err != nil {
		return domainendpoint.Endpoint{}, fmt.Errorf("invalid endpoint URL: %w", err)
	}

	observedAt := input.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}

	return domainendpoint.Endpoint{
		AssetID:        input.AssetID,
		ScanID:         input.ScanID,
		URL:            norm.URL,
		Method:         input.Method,
		Scheme:         norm.Scheme,
		Host:           norm.Host,
		Port:           norm.Port,
		Path:           norm.Path,
		QueryPattern:   norm.QueryPattern,
		ContentType:    input.ContentType,
		ContentLength:  input.ContentLength,
		StatusCode:     input.StatusCode,
		ResponseHash:   input.ResponseHash,
		Classification: input.Classification,
		APIType:        input.APIType,
		APIVersion:     input.APIVersion,
		Sources:        input.Sources,
		Confidence:     input.Confidence,
		Documented:     input.Documented,
		Observed:       input.Observed,
		Inferred:       input.Inferred,
		Metadata:       domainasset.SanitizeMetadata(input.Metadata),
		FirstSeen:      observedAt,
		LastSeen:       observedAt,
	}, nil
}

// UpsertEndpoint normalizes input.URL and persists the resulting endpoint,
// creating it if this is the first observation of its (asset, method,
// normalized URL) or merging into the existing row otherwise.
func (s *Service) UpsertEndpoint(ctx context.Context, input EndpointInput) (domainendpoint.Endpoint, bool, error) {
	e, err := input.toDomain()
	if err != nil {
		return domainendpoint.Endpoint{}, false, apperrors.NewValidation(err.Error(), err)
	}
	if err := e.Validate(); err != nil {
		return domainendpoint.Endpoint{}, false, apperrors.NewValidation("invalid endpoint", err)
	}

	return s.endpoints.Upsert(ctx, e)
}

// EndpointObservationInput extends EndpointInput with the evidence that
// justifies this observation — RecordEndpointObservation persists both
// atomically, mirroring RecordObservation's asset+evidence transaction
// (phase7.md §64: an endpoint must never end up persisted with no
// evidence backing it, when the caller has evidence to record).
type EndpointObservationInput struct {
	Endpoint     EndpointInput
	Source       string
	EvidenceData map[string]any
}

// RecordEndpointObservation upserts the endpoint described by
// input.Endpoint and records input's evidence in a single database
// transaction: if either write fails, neither is applied.
func (s *Service) RecordEndpointObservation(ctx context.Context, input EndpointObservationInput) (domainendpoint.Endpoint, domainendpoint.Evidence, error) {
	e, err := input.Endpoint.toDomain()
	if err != nil {
		return domainendpoint.Endpoint{}, domainendpoint.Evidence{}, apperrors.NewValidation(err.Error(), err)
	}
	if err := e.Validate(); err != nil {
		return domainendpoint.Endpoint{}, domainendpoint.Evidence{}, apperrors.NewValidation("invalid endpoint", err)
	}

	ev := domainendpoint.Evidence{
		Source:       input.Source,
		EvidenceData: domainasset.SanitizeMetadata(input.EvidenceData),
		Confidence:   e.Confidence,
		ObservedAt:   e.FirstSeen,
	}

	var (
		upserted domainendpoint.Endpoint
		recorded domainendpoint.Evidence
	)
	err = s.pool.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		txRepo := endpointrepo.NewPostgresRepository(tx)

		result, _, upsertErr := txRepo.Upsert(ctx, e)
		if upsertErr != nil {
			return upsertErr
		}
		upserted = result

		ev.EndpointID = upserted.ID
		ev.AssetID = upserted.AssetID
		ev.ScanID = e.ScanID
		if err := ev.Validate(); err != nil {
			return apperrors.NewValidation("invalid endpoint evidence", err)
		}

		evResult, _, evidenceErr := txRepo.CreateEvidence(ctx, ev)
		if evidenceErr != nil {
			return evidenceErr
		}
		recorded = evResult
		return nil
	})
	if err != nil {
		return domainendpoint.Endpoint{}, domainendpoint.Evidence{}, err
	}

	return upserted, recorded, nil
}

// ListEndpoints returns a page of endpoints for an asset.
func (s *Service) ListEndpoints(ctx context.Context, filter endpointrepo.ListFilter) (pagination.Page[domainendpoint.Endpoint], error) {
	return s.endpoints.ListByAsset(ctx, filter)
}

// UpdateEndpointStatus explicitly changes an endpoint's lifecycle status.
func (s *Service) UpdateEndpointStatus(ctx context.Context, id uuid.UUID, status domainendpoint.Status) (domainendpoint.Endpoint, error) {
	if !status.Valid() {
		return domainendpoint.Endpoint{}, apperrors.NewValidation("invalid endpoint status", nil)
	}
	return s.endpoints.UpdateStatus(ctx, id, status)
}

// MarkEndpointsInactiveExcept marks every non-INACTIVE endpoint for
// assetID not in stillFound as INACTIVE — the "removed" half of Phase
// 7's change detection (phase7.md §43); rows and their evidence are
// preserved, never deleted.
func (s *Service) MarkEndpointsInactiveExcept(ctx context.Context, assetID uuid.UUID, stillFound []uuid.UUID) ([]domainendpoint.Endpoint, error) {
	return s.endpoints.MarkInactiveExcept(ctx, assetID, stillFound)
}

// UpsertEndpointParameter records a parameter *name* (never a value) as
// observed for an endpoint (phase7.md §9/§37).
func (s *Service) UpsertEndpointParameter(ctx context.Context, input endpointrepo.ParameterInput) (endpointrepo.Parameter, bool, error) {
	return s.endpointParams.UpsertParameter(ctx, input)
}

// ListEndpointParameters returns every parameter observed for endpointID.
func (s *Service) ListEndpointParameters(ctx context.Context, endpointID uuid.UUID) ([]endpointrepo.Parameter, error) {
	return s.endpointParams.ListParameters(ctx, endpointID)
}

// ListEndpointEvidence returns a page of evidence for an endpoint.
func (s *Service) ListEndpointEvidence(ctx context.Context, filter endpointrepo.EvidenceListFilter) (pagination.Page[domainendpoint.Evidence], error) {
	return s.endpointEvidence.ListEvidenceByEndpoint(ctx, filter)
}
