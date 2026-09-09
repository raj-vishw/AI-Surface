// Package fingerprint bridges internal/fingerprint's self-contained
// matching engine to persistence — the same "engine is self-contained,
// the service layer bridges it to the domain model and the database"
// split internal/discovery/service is for the discovery engines
// (phase6.md §47). It builds an Observation entirely from data Phase
// 3/4/5 already persisted, evaluates it, and records the result through
// internal/repository/fingerprint — never performing a network or DNS
// request of its own (phase6.md §46).
package fingerprint

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"ai-surface-platform/internal/database"
	domainasset "ai-surface-platform/internal/domain/asset"
	domainfp "ai-surface-platform/internal/domain/fingerprint"
	apperrors "ai-surface-platform/internal/errors"
	fpengine "ai-surface-platform/internal/fingerprint"
	assetrepo "ai-surface-platform/internal/repository/asset"
	fingerprintrepo "ai-surface-platform/internal/repository/fingerprint"
	"ai-surface-platform/internal/repository/pagination"
	assetsvc "ai-surface-platform/internal/service/asset"
)

// Config configures the service's own behavior — distinct from
// fpengine.EngineConfig, which configures the matching/scoring engine
// itself (passed in already-built via NewService).
type Config struct {
	// ConfidenceChangeThreshold is the minimum |delta| in confidence
	// between two analysis runs of the same (asset, category,
	// technology) fingerprint required to report a "confidence_changed"
	// Change — minor fluctuations are never treated as a technology
	// change (phase6.md §23). 0 uses DefaultConfidenceChangeThreshold.
	ConfidenceChangeThreshold float64
}

// DefaultConfidenceChangeThreshold is the default minimum confidence
// swing worth reporting as a change — anything smaller is noise.
const DefaultConfidenceChangeThreshold = 0.10

// Service orchestrates passive fingerprint analysis end-to-end:
// observation assembly, engine evaluation, and (unless dry-run)
// persistence with historical tracking and change detection.
type Service struct {
	pool     *database.Pool
	repo     fingerprintrepo.Repository
	evidence fingerprintrepo.EvidenceRepository
	assets   *assetsvc.Service
	engine   *fpengine.Engine
	logger   *slog.Logger
	cfg      Config
}

// NewService builds a Service. assets is Phase 2's AssetService (reused,
// never duplicated, phase6.md §24) — this package creates no second
// asset-tracking or database-connection mechanism.
func NewService(pool *database.Pool, assets *assetsvc.Service, engine *fpengine.Engine, logger *slog.Logger, cfg Config) *Service {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if cfg.ConfidenceChangeThreshold <= 0 {
		cfg.ConfidenceChangeThreshold = DefaultConfidenceChangeThreshold
	}
	repo := fingerprintrepo.NewPostgresRepository(pool)
	return &Service{
		pool: pool, repo: repo, evidence: repo, assets: assets, engine: engine, logger: logger, cfg: cfg,
	}
}

// AnalysisResult is one asset's fingerprinting outcome.
type AnalysisResult struct {
	Asset   domainasset.Asset
	Results []fpengine.Result
	Changes []Change
}

// ChangeType names how a fingerprint differs from the asset's previous
// analysis run (phase6.md §23).
type ChangeType string

// Recognized change types.
const (
	ChangeAdded             ChangeType = "added"
	ChangeRemoved           ChangeType = "removed"
	ChangeVersionChanged    ChangeType = "version_changed"
	ChangeConfidenceChanged ChangeType = "confidence_changed"
)

// Change is one detected difference between two analysis runs of the
// same (asset, category, technology) fingerprint (phase6.md §23).
type Change struct {
	AssetID            uuid.UUID
	Category           fpengine.Category
	Technology         string
	Type               ChangeType
	PreviousVersion    string
	CurrentVersion     string
	PreviousConfidence float64
	CurrentConfidence  float64
	DetectedAt         time.Time
}

// Analyze builds an Observation for assetID from already-persisted
// evidence, evaluates it, and — unless dryRun — persists the results and
// returns the changes detected relative to the asset's previous ACTIVE
// fingerprints. In dry-run mode nothing is written and Changes is always
// empty (phase6.md §26's --dry-run).
func (s *Service) Analyze(ctx context.Context, assetID uuid.UUID, scanID *uuid.UUID, dryRun bool) (*AnalysisResult, error) {
	asset, err := s.assets.GetByID(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("loading asset: %w", err)
	}

	obs, err := s.buildObservation(ctx, asset)
	if err != nil {
		return nil, fmt.Errorf("building observation for asset %s: %w", assetID, err)
	}

	results := s.engine.Evaluate(obs)
	s.logger.Info("fingerprint_scan_evaluated", "asset_id", assetID, "matches", len(results))

	result := &AnalysisResult{Asset: asset, Results: results}
	if dryRun {
		return result, nil
	}

	changes, err := s.persist(ctx, asset, results, scanID)
	if err != nil {
		return nil, fmt.Errorf("persisting fingerprints for asset %s: %w", assetID, err)
	}
	result.Changes = changes
	for _, c := range changes {
		s.logger.Info("fingerprint_change_detected",
			"asset_id", assetID, "technology", c.Technology, "category", c.Category, "change_type", c.Type)
	}
	return result, nil
}

// AnalyzeTarget analyzes every asset belonging to targetID. A failure
// analyzing one asset is logged and does not abort the rest (the same
// per-item isolation discipline Phase 3/4/5 apply to persistence
// failures — phase6.md's own "must not become another scanner" principle
// extends to "one bad asset must not break the whole run").
func (s *Service) AnalyzeTarget(ctx context.Context, targetID uuid.UUID, scanID *uuid.UUID, dryRun bool) ([]*AnalysisResult, error) {
	var results []*AnalysisResult
	cursor := ""
	for {
		page, err := s.assets.List(ctx, assetrepo.ListFilter{
			TargetID: targetID, Pagination: pagination.Params{Limit: pagination.MaxLimit, Cursor: cursor},
		})
		if err != nil {
			return nil, fmt.Errorf("listing assets for target %s: %w", targetID, err)
		}
		for _, a := range page.Items {
			r, err := s.Analyze(ctx, a.ID, scanID, dryRun)
			if err != nil {
				s.logger.Error("fingerprint_analysis_failed", "asset_id", a.ID, "target_id", targetID, "error", err)
				continue
			}
			results = append(results, r)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	return results, nil
}

// persist upserts every matched result as a current-state Fingerprint
// plus one Evidence snapshot, all in one transaction (phase6.md §40 —
// a fingerprint must never end up persisted with no evidence backing
// it), marks every previously-ACTIVE fingerprint that no longer matched
// as INACTIVE (never deleted — phase6.md §22), and returns the detected
// Changes relative to the asset's previous ACTIVE state (computed from a
// snapshot taken before this transaction, so a Change always compares
// "before this run" to "after it", never a partially-applied state).
func (s *Service) persist(ctx context.Context, asset domainasset.Asset, results []fpengine.Result, scanID *uuid.UUID) ([]Change, error) {
	previous, err := s.currentFingerprints(ctx, asset.ID)
	if err != nil {
		return nil, err
	}

	matchedIDs := make([]uuid.UUID, 0, len(results))
	currentByKey := make(map[string]fpengine.Result, len(results))

	err = s.pool.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		txRepo := fingerprintrepo.NewPostgresRepository(tx)

		for _, r := range results {
			f := domainfp.Fingerprint{
				AssetID: asset.ID, TargetID: asset.TargetID, ScanID: scanID,
				Category: domainfp.Category(r.Category), Technology: r.Technology,
				Product: r.Product, Vendor: r.Vendor, Version: r.Version,
				Confidence: domainfp.Score(r.Confidence), Status: domainfp.StatusActive,
				Metadata:  buildFingerprintMetadata(r, scanID),
				FirstSeen: asset.LastSeen, LastSeen: asset.LastSeen,
			}
			if err := f.Validate(); err != nil {
				return apperrors.NewValidation("invalid fingerprint", err)
			}

			upserted, _, err := txRepo.Upsert(ctx, f)
			if err != nil {
				return err
			}
			matchedIDs = append(matchedIDs, upserted.ID)
			currentByKey[fingerprintKey(r.Category, r.Technology)] = r

			ev := domainfp.Evidence{
				FingerprintID: upserted.ID, AssetID: asset.ID, ScanID: scanID, Source: "fingerprint",
				Signals: convertSignals(r.Signals), Confidence: domainfp.Score(r.Confidence),
				ObservedAt: asset.LastSeen,
			}
			if err := ev.Validate(); err != nil {
				return apperrors.NewValidation("invalid fingerprint evidence", err)
			}
			if _, _, err := txRepo.CreateEvidence(ctx, ev); err != nil {
				return err
			}
		}

		if _, err := txRepo.MarkInactive(ctx, asset.ID, matchedIDs); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return detectChanges(asset.ID, previous, currentByKey, s.cfg.ConfidenceChangeThreshold), nil
}

// currentFingerprints returns every ACTIVE fingerprint currently
// recorded for assetID, keyed by (category, technology) — the "before"
// snapshot change detection compares against.
func (s *Service) currentFingerprints(ctx context.Context, assetID uuid.UUID) (map[string]domainfp.Fingerprint, error) {
	page, err := s.repo.List(ctx, fingerprintrepo.ListFilter{
		AssetID: assetID, Status: domainfp.StatusActive,
		Pagination: pagination.Params{Limit: pagination.MaxLimit},
	})
	if err != nil {
		return nil, fmt.Errorf("loading previous fingerprints: %w", err)
	}
	out := make(map[string]domainfp.Fingerprint, len(page.Items))
	for _, f := range page.Items {
		out[fingerprintKey(fpengine.Category(f.Category), f.Technology)] = f
	}
	return out, nil
}

func fingerprintKey(category fpengine.Category, technology string) string {
	return string(category) + "|" + technology
}

// detectChanges compares previous (this asset's ACTIVE fingerprints
// before the run) to current (what this run matched), per phase6.md §23.
func detectChanges(assetID uuid.UUID, previous map[string]domainfp.Fingerprint, current map[string]fpengine.Result, threshold float64) []Change {
	now := time.Now().UTC()
	var changes []Change

	for key, prev := range previous {
		if _, stillMatched := current[key]; !stillMatched {
			changes = append(changes, Change{
				AssetID: assetID, Category: fpengine.Category(prev.Category), Technology: prev.Technology,
				Type: ChangeRemoved, PreviousVersion: prev.Version, PreviousConfidence: float64(prev.Confidence),
				DetectedAt: now,
			})
		}
	}

	for key, curr := range current {
		prev, existed := previous[key]
		if !existed {
			changes = append(changes, Change{
				AssetID: assetID, Category: curr.Category, Technology: curr.Technology,
				Type: ChangeAdded, CurrentVersion: curr.Version, CurrentConfidence: curr.Confidence,
				DetectedAt: now,
			})
			continue
		}
		if curr.Version != "" && curr.Version != prev.Version {
			changes = append(changes, Change{
				AssetID: assetID, Category: curr.Category, Technology: curr.Technology,
				Type: ChangeVersionChanged, PreviousVersion: prev.Version, CurrentVersion: curr.Version,
				PreviousConfidence: float64(prev.Confidence), CurrentConfidence: curr.Confidence,
				DetectedAt: now,
			})
		}
		delta := curr.Confidence - float64(prev.Confidence)
		if delta < 0 {
			delta = -delta
		}
		if delta > threshold {
			changes = append(changes, Change{
				AssetID: assetID, Category: curr.Category, Technology: curr.Technology,
				Type: ChangeConfidenceChanged, PreviousConfidence: float64(prev.Confidence), CurrentConfidence: curr.Confidence,
				DetectedAt: now,
			})
		}
	}

	return changes
}

// buildFingerprintMetadata assembles the latest-snapshot Metadata
// attached to a Fingerprint row: the matched signals, folded into a
// display-ready form, plus the scan that produced them — the same
// "latest snapshot on the current-state row, full history in evidence"
// split Phase 5 established for DNS records.
func buildFingerprintMetadata(r fpengine.Result, scanID *uuid.UUID) map[string]any {
	metadata := map[string]any{
		"signature": r.SignatureName,
		"level":     string(r.Level),
	}
	if scanID != nil {
		metadata["scan_id"] = scanID.String()
	}
	signals := make([]any, len(r.Signals))
	for i, s := range r.Signals {
		signals[i] = map[string]any{
			"type": string(s.Type), "field": s.Field, "value": s.Value,
			"weight": s.Weight, "description": s.Description,
		}
	}
	metadata["signals"] = signals
	return metadata
}

// convertSignals translates the engine's live Signal shape into the
// persisted domain shape — the only place the two (deliberately
// separate, see internal/domain/fingerprint's doc comment) types meet.
func convertSignals(signals []fpengine.Signal) []domainfp.Signal {
	out := make([]domainfp.Signal, len(signals))
	for i, s := range signals {
		out[i] = domainfp.Signal{
			Type: string(s.Type), Field: s.Field, Value: s.Value,
			Weight: s.Weight, Description: s.Description,
		}
	}
	return out
}

// List returns a page of persisted fingerprints matching filter — used
// by the CLI/future API to inspect current or historical state without
// re-running analysis.
func (s *Service) List(ctx context.Context, filter fingerprintrepo.ListFilter) (pagination.Page[domainfp.Fingerprint], error) {
	return s.repo.List(ctx, filter)
}

// ListEvidence returns a page of evidence for a fingerprint.
func (s *Service) ListEvidence(ctx context.Context, filter fingerprintrepo.EvidenceListFilter) (pagination.Page[domainfp.Evidence], error) {
	return s.evidence.ListEvidenceByFingerprint(ctx, filter)
}
