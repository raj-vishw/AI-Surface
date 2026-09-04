// Package detection bridges internal/detection's self-contained engine to
// persistence — the same "engine is self-contained, the service layer
// bridges it to the domain model and the database" split
// internal/service/fingerprint is for internal/fingerprint (phase8.md
// §1/§53). It builds a detection.Input entirely from data Phase 2-7
// already persisted, evaluates it, and records the result through
// internal/repository/finding — issuing a fresh network request of its
// own only when explicitly running in safe-active mode, and even then
// only through the same Phase 1 HTTP client and Phase 3 ScopeValidator
// every other discovery engine in this project reuses.
package detection

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/database"
	"ai-recon-platform/internal/detection"
	discoveryhttp "ai-recon-platform/internal/discovery/http"
	domainasset "ai-recon-platform/internal/domain/asset"
	domainfinding "ai-recon-platform/internal/domain/finding"
	domaintarget "ai-recon-platform/internal/domain/target"
	apperrors "ai-recon-platform/internal/errors"
	"ai-recon-platform/internal/httpclient"
	assetrepo "ai-recon-platform/internal/repository/asset"
	findingrepo "ai-recon-platform/internal/repository/finding"
	fingerprintrepo "ai-recon-platform/internal/repository/fingerprint"
	"ai-recon-platform/internal/repository/pagination"
	assetsvc "ai-recon-platform/internal/service/asset"
	targetsvc "ai-recon-platform/internal/service/target"
)

// detectableAssetTypes are the asset types findings are computed against
// — the same HTTP/API/AI endpoint types Phase 3/7 produce, since those
// are the ones carrying the Endpoint (Phase 7) and per-response Metadata
// (Phase 3) a detector needs.
var detectableAssetTypes = []domainasset.Type{
	domainasset.TypeHTTPEndpoint, domainasset.TypeAPIEndpoint, domainasset.TypeAIEndpoint,
}

// Service orchestrates finding detection end-to-end: observation
// assembly, engine evaluation, and (unless dry-run) persistence with
// historical lifecycle tracking.
type Service struct {
	pool         *database.Pool
	targets      *targetsvc.Service
	assets       *assetsvc.Service
	findings     findingrepo.Repository
	evidence     findingrepo.EvidenceRepository
	events       findingrepo.EventRepository
	fingerprints fingerprintrepo.Repository
	registry     *detection.Registry
	engine       *detection.Engine
	logger       *slog.Logger
}

// NewService builds a Service. assets/targets are Phase 2's services and
// fingerprints is Phase 6's repository (all reused, never duplicated —
// phase8.md §1). registry must already have every detector this
// deployment wants registered (see internal/detection/detectors.
// RegisterAll).
func NewService(pool *database.Pool, targets *targetsvc.Service, assets *assetsvc.Service, fingerprints fingerprintrepo.Repository, registry *detection.Registry, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	repo := findingrepo.NewPostgresRepository(pool)
	return &Service{
		pool: pool, targets: targets, assets: assets,
		findings: repo, evidence: repo, events: repo,
		fingerprints: fingerprints, registry: registry, engine: detection.NewEngine(registry), logger: logger,
	}
}

// Request describes one detection run.
type Request struct {
	TargetType  domaintarget.Type
	TargetValue string
	// Mode defaults to detection.ModePassive when empty (phase8.md §54).
	Mode   detection.Mode
	ScanID *uuid.UUID
	DryRun bool
	Config detection.Config
}

// DryRunReport is returned instead of a RunResult when req.DryRun is true
// — no HTTP request is made and nothing is persisted (phase8.md §55).
type DryRunReport struct {
	Target           string
	Mode             detection.Mode
	EnabledDetectors []string
	// NetworkRequests is always 0 for a dry run — see phase8.md §55's
	// worked example.
	NetworkRequests int
}

// Change is one detected lifecycle transition from this run (phase8.md
// §75).
type Change struct {
	FindingID   uuid.UUID
	IdentityKey string
	Title       string
	AssetID     uuid.UUID
	EndpointID  *uuid.UUID
	Type        detection.ChangeType
	DetectedAt  time.Time
}

// RunResult is one non-dry-run detection run's outcome.
type RunResult struct {
	ScanID         uuid.UUID
	Target         domaintarget.Target
	AssetsAnalyzed int
	Findings       []domainfinding.Finding
	Changes        []Change
	DetectorErrors []detection.DetectorError
}

// Run loads and (for safe-active mode) authorizes req's target, then
// either reports the detectors that would run (DryRunReport) or executes
// detection against every HTTP/API/AI-endpoint asset already known for
// the target and persists the result (*RunResult). Exactly one of the two
// return values is non-nil on success.
func (s *Service) Run(ctx context.Context, req Request) (*RunResult, *DryRunReport, error) {
	mode := req.Mode
	if mode == "" {
		mode = detection.ModePassive
	}
	if !mode.Valid() {
		return nil, nil, apperrors.NewValidation(fmt.Sprintf("mode %q is not recognized (passive|safe_active)", mode), nil)
	}

	target, err := s.targets.GetByValue(ctx, req.TargetType, req.TargetValue)
	if err != nil {
		return nil, nil, fmt.Errorf("loading target: %w", err)
	}
	if err := target.Validate(); err != nil {
		return nil, nil, fmt.Errorf("target is invalid: %w", err)
	}
	// Safe-active mode issues real requests, so it requires the same
	// authorization boundary every active discovery phase enforces
	// (phase8.md §13/§84). Pure passive analysis reads only
	// already-persisted evidence and performs no request of its own,
	// mirroring Phase 6's fingerprint command, which imposes no such
	// check either.
	if mode == detection.ModeSafeActive && !target.IsAuthorized() {
		return nil, nil, apperrors.NewForbidden("target is not authorized for active (safe-active) detection", nil)
	}

	if req.DryRun {
		names := make([]string, 0)
		for _, d := range s.registry.Active(mode) {
			if !req.Config.DetectorEnabled(d.ID()) {
				continue
			}
			names = append(names, d.ID())
		}
		return nil, &DryRunReport{Target: req.TargetValue, Mode: mode, EnabledDetectors: names, NetworkRequests: 0}, nil
	}

	scanID := uuid.New()
	if req.ScanID != nil {
		scanID = *req.ScanID
	}

	var fetcher detection.SafeActiveFetcher
	if mode == detection.ModeSafeActive {
		scope, err := discoveryhttp.NewScopeValidator(scopeSeedURL(req.TargetType, req.TargetValue))
		if err != nil {
			return nil, nil, fmt.Errorf("building scope validator: %w", err)
		}
		fetcher = detection.NewHTTPFetcher(newScopedClient(req.Config, scope))
	}

	serviceObs, err := s.loadServiceObservations(ctx, target.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("loading network observations: %w", err)
	}

	result := &RunResult{ScanID: scanID, Target: target}

	cursor := ""
	for {
		page, err := s.assets.List(ctx, buildAssetFilter(target.ID, cursor))
		if err != nil {
			return nil, nil, fmt.Errorf("listing assets for target %s: %w", target.ID, err)
		}
		for _, a := range page.Items {
			if !isDetectableType(a.Type) {
				continue
			}
			if err := s.analyzeAsset(ctx, a, target.ID, scanID, mode, fetcher, req.Config, serviceObs, result); err != nil {
				s.logger.Error("finding_detection_asset_failed", "asset_id", a.ID, "target_id", target.ID, "error", err)
				continue
			}
			result.AssetsAnalyzed++
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	return result, nil, nil
}

func buildAssetFilter(targetID uuid.UUID, cursor string) assetrepo.ListFilter {
	return assetrepo.ListFilter{TargetID: targetID, Pagination: pagination.Params{Limit: pagination.MaxLimit, Cursor: cursor}}
}

func isDetectableType(t domainasset.Type) bool {
	for _, typ := range detectableAssetTypes {
		if t == typ {
			return true
		}
	}
	return false
}

// scopeSeedURL mirrors internal/discovery/service's own helper — a URL
// target's own value is the scope seed, otherwise a synthetic https URL
// (scheme is irrelevant, only the host is extracted).
func scopeSeedURL(targetType domaintarget.Type, value string) string {
	if targetType == domaintarget.TypeURL {
		return value
	}
	return "https://" + value
}

// newScopedClient builds an internal/httpclient.Client whose redirect
// policy is bound to scope — the same NewClientForScope pattern Phase
// 3/7 each already establish (phase8.md §1's "do not create duplicate
// HTTP clients / scope validators"), reimplemented here (rather than
// imported) only because Phase 3's lives in an internal package scoped to
// its own Config type; the *behavior* (Options.AllowRedirectTo bound to
// scope.Allowed) is identical.
func newScopedClient(cfg detection.Config, scope *discoveryhttp.ScopeValidator) *httpclient.Client {
	timeout := cfg.RequestTimeout
	if timeout <= 0 {
		timeout = detection.DefaultRequestTimeout
	}
	maxSize := cfg.MaxResponseSize
	if maxSize <= 0 {
		maxSize = detection.DefaultMaxResponseSize
	}
	return httpclient.New(httpclient.Options{
		Timeout: timeout, MaxResponseSize: maxSize, MaxRedirects: 3, AllowRedirectTo: scope.Allowed,
	})
}

// assetOrigin extracts scheme/host/port from a's URL (preferred) or its
// Protocol/Hostname/Port fields, for baseOrigin-style safe-active
// requests.
func assetOrigin(a domainasset.Asset) (scheme, host string, port int) {
	if a.URL != nil && *a.URL != "" {
		if u, err := url.Parse(*a.URL); err == nil {
			scheme = u.Scheme
			host = u.Hostname()
			if p := u.Port(); p != "" {
				if n, err := strconv.Atoi(p); err == nil {
					port = n
				}
			}
			if port == 0 {
				port = defaultPortForScheme(scheme)
			}
			return scheme, host, port
		}
	}
	scheme = domainasset.StringField(a.Protocol)
	host = domainasset.StringField(a.Hostname)
	if a.Port != nil {
		port = *a.Port
	} else {
		port = defaultPortForScheme(scheme)
	}
	return scheme, host, port
}

func defaultPortForScheme(scheme string) int {
	if scheme == "https" {
		return 443
	}
	return 80
}

// loadServiceObservations pages through every asset for targetID and
// returns Phase 4's PORT/SERVICE observations, grouped by hostname —
// used to correlate an HTTP/API/AI asset with its sibling TCP/TLS
// evidence (see types.go's TLSObservation/ServiceObservation).
func (s *Service) loadServiceObservations(ctx context.Context, targetID uuid.UUID) (map[string][]domainasset.Asset, error) {
	out := map[string][]domainasset.Asset{}
	cursor := ""
	for {
		page, err := s.assets.List(ctx, buildAssetFilter(targetID, cursor))
		if err != nil {
			return nil, err
		}
		for _, a := range page.Items {
			if a.Type != domainasset.TypePort && a.Type != domainasset.TypeService {
				continue
			}
			host := domainasset.StringField(a.Hostname)
			if host == "" {
				host = domainasset.StringField(a.IP)
			}
			out[host] = append(out[host], a)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	return out, nil
}
