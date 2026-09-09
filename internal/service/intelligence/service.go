// Package intelligence bridges internal/intelligence's self-contained
// provider/aggregation/vulnerability-matching engine and
// internal/intelligence/risk's scorer to persistence — the same "engine
// is self-contained, the service layer bridges it to the domain model and
// the database" split every prior phase's service package follows
// (phase10.md §1). It builds internal/intelligence/providers.LocalDataset
// entirely from data Phase 2-8 already persisted (asset metadata,
// fingerprints, findings), evaluates it, and records the result through
// internal/repository/intelligence.
package intelligence

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/database"
	domainasset "ai-surface-platform/internal/domain/asset"
	domainintel "ai-surface-platform/internal/domain/intelligence"
	domaintarget "ai-surface-platform/internal/domain/target"
	"ai-surface-platform/internal/intelligence"
	"ai-surface-platform/internal/intelligence/providers"
	"ai-surface-platform/internal/intelligence/risk"
	assetrepo "ai-surface-platform/internal/repository/asset"
	correlationrepo "ai-surface-platform/internal/repository/correlation"
	endpointrepo "ai-surface-platform/internal/repository/endpoint"
	findingrepo "ai-surface-platform/internal/repository/finding"
	fingerprintrepo "ai-surface-platform/internal/repository/fingerprint"
	intelrepo "ai-surface-platform/internal/repository/intelligence"
	investigationrepo "ai-surface-platform/internal/repository/investigation"
	"ai-surface-platform/internal/repository/pagination"
	rulerepo "ai-surface-platform/internal/repository/rule"
	assetsvc "ai-surface-platform/internal/service/asset"
	targetsvc "ai-surface-platform/internal/service/target"
)

// Service orchestrates every intelligence and risk operation.
type Service struct {
	pool *database.Pool

	targets        *targetsvc.Service
	assets         *assetsvc.Service
	endpoints      endpointrepo.Repository
	fingerprints   fingerprintrepo.Repository
	findings       findingrepo.Repository
	investigations *investigationrepo.PostgresRepository

	records intelrepo.RecordRepository
	vulns   intelrepo.VulnerabilityRepository
	risks   intelrepo.RiskRepository
	events  intelrepo.EventRepository
	crit    intelrepo.CriticalityRepository
	cache   intelligence.Cache

	registry      *intelligence.Registry
	engine        *intelligence.Engine
	datasetSource *providers.DatasetSource
	scorer        *risk.Scorer

	// detectionMatches is Phase 11's optional risk-model extension
	// (phase11.md §98) — nil unless a caller opts in via
	// WithDetectionMatches, so a deployment that hasn't wired Phase 11
	// still gets a normal (zero-contribution) risk calculation. See
	// buildAssetRiskInput.
	detectionMatches rulerepo.MatchRepository

	// correlations is Phase 12's identically-shaped optional risk-model
	// extension (phase12.md §34) — nil unless a caller opts in via
	// WithCorrelations.
	correlations correlationrepo.Repository

	cfg    intelligence.Config
	logger *slog.Logger
}

// WithDetectionMatches opts a Service into Phase 11's "detection_match"
// risk factor (phase11.md §98) — CLI wiring that has already built a
// Phase 11 repository may call this once after NewService. Returns s for
// chaining.
func (s *Service) WithDetectionMatches(m rulerepo.MatchRepository) *Service {
	s.detectionMatches = m
	return s
}

// WithCorrelations opts a Service into Phase 12's "correlation" risk
// factor (phase12.md §34) — CLI wiring that has already built a Phase 12
// repository may call this once after NewService. Returns s for chaining.
func (s *Service) WithCorrelations(c correlationrepo.Repository) *Service {
	s.correlations = c
	return s
}

// NewService builds a Service. targets/assets are Phase 2's services;
// endpoints/fingerprints/findings are Phase 6/7/8's repositories, all
// reused directly (never duplicated — phase10.md §1). registry must
// already have every provider this deployment wants registered, and
// datasetSource must be the SAME *providers.DatasetSource instance those
// registered Local/DNS/Certificate/Technology providers were built with
// (see providers.DatasetSource's doc comment) — this service updates it
// before every provider lookup that needs local data.
func NewService(pool *database.Pool, targets *targetsvc.Service, assets *assetsvc.Service, registry *intelligence.Registry, datasetSource *providers.DatasetSource, cfg intelligence.Config, weights risk.Weights, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if datasetSource == nil {
		datasetSource = providers.NewDatasetSource()
	}
	repo := intelrepo.NewPostgresRepository(pool)
	return &Service{
		pool: pool, targets: targets, assets: assets,
		endpoints:      endpointrepo.NewPostgresRepository(pool),
		fingerprints:   fingerprintrepo.NewPostgresRepository(pool),
		findings:       findingrepo.NewPostgresRepository(pool),
		investigations: investigationrepo.NewPostgresRepository(pool),
		records:        repo, vulns: repo, risks: repo, events: repo, crit: repo,
		cache:    newPostgresCache(repo),
		registry: registry, engine: intelligence.NewEngine(registry), datasetSource: datasetSource,
		scorer: risk.NewScorer(weights), cfg: cfg, logger: logger,
	}
}

// ResolveTarget loads the target for (targetType, targetValue) — the
// same convention internal/service/detection and internal/service/
// investigation use.
func (s *Service) ResolveTarget(ctx context.Context, targetType domaintarget.Type, targetValue string) (domaintarget.Target, error) {
	return s.targets.GetByValue(ctx, targetType, targetValue)
}

// GetAsset returns the asset with the given id.
func (s *Service) GetAsset(ctx context.Context, assetID uuid.UUID) (domainasset.Asset, error) {
	return s.assets.GetByID(ctx, assetID)
}

// ListTargetAssets returns a page of assets belonging to targetID —
// exposed for `ai-surface intel enrich-project`'s bounded batch enrichment
// (phase10.md §71).
func (s *Service) ListTargetAssets(ctx context.Context, targetID uuid.UUID, params pagination.Params) (pagination.Page[domainasset.Asset], error) {
	return s.assets.List(ctx, assetrepo.ListFilter{TargetID: targetID, Pagination: params})
}

// LookupReport is one Lookup call's outcome.
type LookupReport struct {
	Indicator      intelligence.Indicator
	Records        []domainintel.Record
	Aggregated     intelligence.AggregatedResult
	ProviderErrors []intelligence.ProviderError
	CacheHits      []string
}

// Enrich runs the engine against one indicator, persists every record it
// produces, and returns the aggregated view — the active operation behind
// `ai-surface intel enrich` (phase10.md §61/§72). See Show for the
// read-only counterpart behind `ai-surface intel lookup`. It resolves any
// already-known asset matching indicator so Local/DNS/Certificate/
// Technology providers see that asset's data (phase10.md §7/§31); an
// indicator with no matching asset still runs against an empty local
// dataset plus any enabled external provider.
func (s *Service) Enrich(ctx context.Context, targetID uuid.UUID, indicator intelligence.Indicator) (LookupReport, error) {
	dataset := s.datasetForIndicator(ctx, targetID, indicator)
	return s.enrichWithDataset(ctx, targetID, indicator, dataset)
}

// datasetForIndicator resolves the already-known asset (if any) matching
// indicator within targetID and builds its LocalDataset — never a new
// network request or a pivot into unrelated infrastructure (phase10.md
// §31/§32).
func (s *Service) datasetForIndicator(ctx context.Context, targetID uuid.UUID, indicator intelligence.Indicator) providers.LocalDataset {
	filter := assetrepo.ListFilter{TargetID: targetID, Pagination: pagination.Params{Limit: 1}}
	switch indicator.Type {
	case intelligence.IndicatorDomain, intelligence.IndicatorSubdomain, intelligence.IndicatorHostname:
		filter.Hostname = indicator.Value
	case intelligence.IndicatorIPv4, intelligence.IndicatorIPv6:
		filter.IP = indicator.Value
	default:
		return providers.NewLocalDataset()
	}
	page, err := s.assets.List(ctx, filter)
	if err != nil || len(page.Items) == 0 {
		return providers.NewLocalDataset()
	}
	return s.buildLocalDataset(ctx, page.Items[0])
}

// enrichWithDataset is Enrich's implementation once the caller has
// already resolved (or deliberately chosen) the LocalDataset to use —
// EnrichAsset calls this directly, once per asset indicator, reusing the
// same already-built dataset rather than re-resolving it on every call.
func (s *Service) enrichWithDataset(ctx context.Context, targetID uuid.UUID, indicator intelligence.Indicator, dataset providers.LocalDataset) (LookupReport, error) {
	s.datasetSource.Set(dataset)

	before, _ := s.Show(ctx, targetID, indicator)

	result := s.engine.Lookup(ctx, indicator, s.cfg, s.cache)

	stored := make([]domainintel.Record, 0, len(result.Records))
	for _, rec := range result.Records {
		domainRec := toDomainRecord(targetID, rec)
		saved, _, err := s.records.UpsertRecord(ctx, domainRec)
		if err != nil {
			s.logger.Error("intelligence_record_persist_failed", "provider_id", rec.ProviderID, "indicator", rec.Indicator.Key(), "error", err)
			continue
		}
		stored = append(stored, saved)
	}

	fresh := intelligence.FreshRecords(result.Records, time.Now())
	aggregated := intelligence.Aggregate(fresh, s.cfg.Weights)

	s.emitVerdictChangeEvents(ctx, targetID, result.Indicator, before.Aggregated, aggregated)

	return LookupReport{
		Indicator: result.Indicator, Records: stored, Aggregated: aggregated,
		ProviderErrors: result.Errors, CacheHits: result.CacheHits,
	}, nil
}

// emitVerdictChangeEvents records an EnrichmentEvent when the aggregated
// verdict actually changed between two Enrich calls (phase10.md §48/§49)
// — never on the first-ever observation (before.Verdict == "" means "no
// prior aggregate existed").
func (s *Service) emitVerdictChangeEvents(ctx context.Context, targetID uuid.UUID, indicator intelligence.Indicator, before, after intelligence.AggregatedResult) {
	if before.Verdict == "" || before.Verdict == after.Verdict {
		return
	}
	eventType := domainintel.EventVerdictChanged
	if after.Verdict == intelligence.VerdictMalicious {
		eventType = domainintel.EventNewMaliciousReputation
	}
	_, err := s.events.RecordEvent(ctx, domainintel.EnrichmentEvent{
		TargetID: targetID, IndicatorType: domainintel.IndicatorType(indicator.Type), IndicatorValue: indicator.Value,
		EventType: eventType, Source: "aggregation", Timestamp: time.Now().UTC(),
		PreviousValue: string(before.Verdict), NewValue: string(after.Verdict), Confidence: domainintel.Confidence(after.Confidence),
	})
	if err != nil {
		s.logger.Error("intelligence_event_record_failed", "indicator", indicator.Key(), "error", err)
	}
}

// Show returns the aggregated view built ONLY from already-persisted
// records — no provider is queried (phase10.md §61's `ai-surface intel
// lookup`, distinct from the active `ai-surface intel enrich`).
func (s *Service) Show(ctx context.Context, targetID uuid.UUID, indicator intelligence.Indicator) (LookupReport, error) {
	normalized := intelligence.Normalize(indicator)
	stored, err := s.records.ListRecordsByIndicator(ctx, targetID, domainintel.IndicatorType(normalized.Type), normalized.Value)
	if err != nil {
		return LookupReport{}, err
	}
	engineRecords := make([]intelligence.Record, 0, len(stored))
	for _, rec := range stored {
		engineRecords = append(engineRecords, toEngineRecord(rec))
	}
	fresh := intelligence.FreshRecords(engineRecords, time.Now())
	return LookupReport{
		Indicator: normalized, Records: stored, Aggregated: intelligence.Aggregate(fresh, s.cfg.Weights),
	}, nil
}

// Plan reports which providers Enrich would query without performing any
// lookup (phase10.md §72's --dry-run) — the same list for every
// indicator under the current configuration (see Engine.Plan).
func (s *Service) Plan() []string {
	return s.engine.Plan(s.cfg)
}

// Refresh invalidates every provider's cache entry for indicator, then
// re-runs Enrich (phase10.md §24).
func (s *Service) Refresh(ctx context.Context, targetID uuid.UUID, indicator intelligence.Indicator) (LookupReport, error) {
	normalized := intelligence.Normalize(indicator)
	for _, p := range s.registry.Active() {
		key := intelligence.CacheKey{ProviderID: p.ID(), Indicator: normalized}
		if err := s.cache.Invalidate(ctx, key); err != nil {
			s.logger.Error("intelligence_cache_invalidate_failed", "provider_id", p.ID(), "error", err)
		}
	}
	return s.Enrich(ctx, targetID, normalized)
}

// ProviderStatus reports one provider's configuration and health
// (phase10.md §61's "ai-surface intel providers" / §74).
type ProviderStatus struct {
	intelligence.ProviderMeta
	Health intelligence.ProviderHealth
}

// ProvidersStatus returns every registered provider's status.
func (s *Service) ProvidersStatus() []ProviderStatus {
	meta := s.registry.Metadata()
	out := make([]ProviderStatus, len(meta))
	for i, m := range meta {
		health, _ := s.registry.Health(m.ID)
		out[i] = ProviderStatus{ProviderMeta: m, Health: health}
	}
	return out
}

// toDomainRecord maps an engine Record onto the persisted domain shape.
func toDomainRecord(targetID uuid.UUID, r intelligence.Record) domainintel.Record {
	return domainintel.Record{
		TargetID:      targetID,
		IndicatorType: domainintel.IndicatorType(r.Indicator.Type), IndicatorValue: r.Indicator.Value,
		ProviderID: r.ProviderID, ProviderVersion: r.ProviderVersion, SourceType: r.SourceType,
		Category: domainintel.Category(r.Category), Verdict: domainintel.Verdict(r.Verdict), Confidence: domainintel.Confidence(r.Confidence),
		FirstSeen: r.FirstSeen, LastSeen: r.LastSeen, Expiration: r.Expiration, RetrievedAt: r.RetrievedAt,
		SourceReference: r.SourceReference, NormalizedData: r.NormalizedData, Tags: r.Tags,
	}
}

func toEngineRecord(r domainintel.Record) intelligence.Record {
	return intelligence.Record{
		Indicator:  intelligence.Indicator{Type: intelligence.IndicatorType(r.IndicatorType), Value: r.IndicatorValue},
		ProviderID: r.ProviderID, ProviderVersion: r.ProviderVersion, SourceType: r.SourceType,
		Category: intelligence.Category(r.Category), Verdict: intelligence.Verdict(r.Verdict), Confidence: intelligence.Confidence(r.Confidence),
		FirstSeen: r.FirstSeen, LastSeen: r.LastSeen, Expiration: r.Expiration, RetrievedAt: r.RetrievedAt,
		SourceReference: r.SourceReference, NormalizedData: r.NormalizedData, Tags: r.Tags,
	}
}

// indicatorsForAsset derives every indicator worth looking up for an
// asset — its hostname/IP/URL — never more than that (phase10.md §31/§32:
// only known in-scope indicators, no pivoting into unrelated
// infrastructure).
func indicatorsForAsset(a domainasset.Asset) []intelligence.Indicator {
	var out []intelligence.Indicator
	if a.Hostname != nil && *a.Hostname != "" {
		typ := intelligence.IndicatorHostname
		switch a.Type {
		case domainasset.TypeDomain:
			typ = intelligence.IndicatorDomain
		case domainasset.TypeSubdomain:
			typ = intelligence.IndicatorSubdomain
		}
		out = append(out, intelligence.Indicator{Type: typ, Value: *a.Hostname})
	}
	if a.IP != nil && *a.IP != "" {
		typ := intelligence.IndicatorIPv4
		if strings.Contains(*a.IP, ":") {
			typ = intelligence.IndicatorIPv6
		}
		out = append(out, intelligence.Indicator{Type: typ, Value: *a.IP})
	}
	if a.URL != nil && *a.URL != "" {
		out = append(out, intelligence.Indicator{Type: intelligence.IndicatorURL, Value: *a.URL})
	}
	return out
}

// hostKeyForAsset returns the host string LocalDataset entries for a are
// keyed under — hostname if known, otherwise IP.
func hostKeyForAsset(a domainasset.Asset) string {
	if a.Hostname != nil && *a.Hostname != "" {
		return *a.Hostname
	}
	if a.IP != nil {
		return *a.IP
	}
	return ""
}

// buildLocalDataset assembles a providers.LocalDataset scoped to one
// asset from already-persisted Phase 2/5/6 data — never fetched by a
// Provider itself (phase10.md §7/§8/§9/§11).
func (s *Service) buildLocalDataset(ctx context.Context, a domainasset.Asset) providers.LocalDataset {
	ds := providers.NewLocalDataset()
	host := hostKeyForAsset(a)
	if host == "" {
		return ds
	}

	if a.Type == domainasset.TypeDomain || a.Type == domainasset.TypeSubdomain {
		ds.DNSRecords[host] = dnsRecordsFromMetadata(a.Metadata)
	}
	if a.Type == domainasset.TypePort || a.Type == domainasset.TypeService {
		if cert, ok := certificateFromMetadata(host, a.Metadata); ok {
			ds.Certificates[host] = cert
		}
	}

	fpPage, err := s.fingerprints.List(ctx, fingerprintrepo.ListFilter{AssetID: a.ID, Pagination: pagination.Params{Limit: pagination.MaxLimit}})
	if err != nil {
		s.logger.Error("intelligence_fingerprint_list_failed", "asset_id", a.ID, "error", err)
	} else {
		for _, fp := range fpPage.Items {
			ds.Technologies[host] = append(ds.Technologies[host], providers.TechnologyObservation{
				Product: fp.Technology, Vendor: fp.Vendor, Version: fp.Version,
				Category: string(fp.Category), Confidence: float64(fp.Confidence),
			})
		}
	}

	openFindings, err := s.findings.List(ctx, findingrepo.ListFilter{AssetID: a.ID, Pagination: pagination.Params{Limit: pagination.MaxLimit}})
	if err != nil {
		s.logger.Error("intelligence_finding_list_failed", "asset_id", a.ID, "error", err)
	}
	findingCount := 0
	if err == nil {
		for _, f := range openFindings.Items {
			if f.Status.Open() {
				findingCount++
			}
		}
	}
	recentlyChanged := time.Since(a.UpdatedAt) < 7*24*time.Hour
	ds.AssetHistory[host] = providers.AssetHistoryObservation{
		FirstSeen: a.FirstSeen, LastSeen: a.LastSeen, FindingCount: findingCount, RecentlyChanged: recentlyChanged,
	}
	// AssetHistory is also keyed by hostname/IP indicator values (which
	// equal host here), and additionally by the asset's URL if it has
	// one, so LocalProvider recognizes every indicator derived from this
	// asset (see indicatorsForAsset).
	if a.URL != nil && *a.URL != "" {
		ds.AssetHistory[*a.URL] = ds.AssetHistory[host]
	}

	return ds
}

func dnsRecordsFromMetadata(metadata map[string]any) []providers.DNSRecordObservation {
	var out []providers.DNSRecordObservation
	addAll := func(recordType, key string) {
		vals, ok := metadata[key]
		if !ok {
			return
		}
		list, ok := vals.([]any)
		if !ok {
			return
		}
		for _, v := range list {
			if s, ok := v.(string); ok {
				out = append(out, providers.DNSRecordObservation{Type: recordType, Value: s})
			}
		}
	}
	addAll("A", "a_records")
	addAll("AAAA", "aaaa_records")
	addAll("MX", "mx_records")
	addAll("NS", "ns_records")
	addAll("TXT", "txt_records")
	if cname, ok := metadata["cname_target"].(string); ok && cname != "" {
		out = append(out, providers.DNSRecordObservation{Type: "CNAME", Value: cname})
	}
	return out
}

func certificateFromMetadata(host string, metadata map[string]any) (providers.CertificateObservation, bool) {
	subject, _ := metadata["certificate_subject"].(string)
	issuer, _ := metadata["certificate_issuer"].(string)
	if subject == "" && issuer == "" {
		return providers.CertificateObservation{}, false
	}
	cert := providers.CertificateObservation{Host: host, Subject: subject, Issuer: issuer}
	if notAfter, ok := metadata["certificate_not_after"].(string); ok && notAfter != "" {
		if t, err := time.Parse(time.RFC3339, notAfter); err == nil {
			cert.NotAfter = t
		}
	}
	return cert, true
}
