package detection

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"ai-surface-platform/internal/detection"
	domainasset "ai-surface-platform/internal/domain/asset"
	domainfinding "ai-surface-platform/internal/domain/finding"
	domainfp "ai-surface-platform/internal/domain/fingerprint"
	apperrors "ai-surface-platform/internal/errors"
	endpointrepo "ai-surface-platform/internal/repository/endpoint"
	findingrepo "ai-surface-platform/internal/repository/finding"
	fingerprintrepo "ai-surface-platform/internal/repository/fingerprint"
	"ai-surface-platform/internal/repository/pagination"
)

// analyzeAsset builds a detection.Input for asset from already-persisted
// Phase 3/4/6/7 data, evaluates it, and persists every resulting finding,
// accumulating findings/changes/errors into result.
func (s *Service) analyzeAsset(
	ctx context.Context, asset domainasset.Asset, targetID, scanID uuid.UUID, mode detection.Mode,
	fetcher detection.SafeActiveFetcher, cfg detection.Config, serviceObsByHost map[string][]domainasset.Asset,
	result *RunResult,
) error {
	input, err := s.buildInput(ctx, asset, mode, fetcher, cfg, serviceObsByHost)
	if err != nil {
		return fmt.Errorf("building detection input: %w", err)
	}

	engineResult := s.engine.Evaluate(ctx, input)
	for _, detErr := range engineResult.Errors {
		result.DetectorErrors = append(result.DetectorErrors, detErr)
		s.logger.Error("detector_failed", "detector_id", detErr.DetectorID, "asset_id", asset.ID, "error", detErr.Err)
	}

	currentIDs := make([]uuid.UUID, 0, len(engineResult.Findings))
	for _, f := range engineResult.Findings {
		persisted, change, err := s.persistFinding(ctx, f, targetID, scanID)
		if err != nil {
			s.logger.Error("finding_persist_failed", "detector_id", f.DetectorID, "asset_id", asset.ID, "error", err)
			continue
		}
		currentIDs = append(currentIDs, persisted.ID)
		result.Findings = append(result.Findings, persisted)
		if change != nil {
			result.Changes = append(result.Changes, *change)
		}
	}

	resolved, err := s.findings.ResolveMissing(ctx, asset.ID, currentIDs)
	if err != nil {
		return fmt.Errorf("resolving missing findings: %w", err)
	}
	for _, f := range resolved {
		// f.Status already reflects the post-transition value (resolved);
		// the exact pre-transition state (open vs reopened) isn't
		// returned by ResolveMissing, so FromStatus is left blank rather
		// than guessed — Event.Validate accepts an empty FromStatus.
		s.recordEvent(ctx, f.ID, &scanID, domainfinding.EventResolved, "", domainfinding.StatusResolved, f.Severity, f.Confidence, "")
		result.Changes = append(result.Changes, Change{
			FindingID: f.ID, IdentityKey: f.IdentityKey, Title: f.Title, AssetID: f.AssetID, EndpointID: f.EndpointID,
			Type: detection.ChangeResolved, DetectedAt: time.Now().UTC(),
		})
	}

	return nil
}

// buildInput assembles a detection.Input for asset entirely from
// already-persisted Phase 3/4/6/7 data — the only place this package
// reads from the database to construct engine input.
func (s *Service) buildInput(ctx context.Context, asset domainasset.Asset, mode detection.Mode, fetcher detection.SafeActiveFetcher, cfg detection.Config, serviceObsByHost map[string][]domainasset.Asset) (detection.Input, error) {
	scheme, host, port := assetOrigin(asset)

	endpoints, err := s.loadEndpoints(ctx, asset.ID)
	if err != nil {
		return detection.Input{}, err
	}

	fingerprints, err := s.loadFingerprints(ctx, asset.ID)
	if err != nil {
		return detection.Input{}, err
	}

	hostKey := domainasset.StringField(asset.Hostname)
	if hostKey == "" {
		hostKey = domainasset.StringField(asset.IP)
	}
	tlsObs, serviceObs := convertServiceObservations(serviceObsByHost[hostKey])

	return detection.Input{
		Asset: detection.AssetObservation{
			ID: asset.ID, TargetID: asset.TargetID, Type: string(asset.Type),
			Hostname: domainasset.StringField(asset.Hostname), IP: domainasset.StringField(asset.IP),
			URL: domainasset.StringField(asset.URL), Scheme: scheme, Host: host, Port: port,
			Confidence: float64(asset.Confidence), Metadata: asset.Metadata,
			FirstSeen: asset.FirstSeen, LastSeen: asset.LastSeen,
		},
		Endpoints: endpoints, TLS: tlsObs, Services: serviceObs, Fingerprints: fingerprints,
		Mode: mode, Fetcher: fetcher, Config: cfg,
	}, nil
}

func (s *Service) loadEndpoints(ctx context.Context, assetID uuid.UUID) ([]detection.EndpointObservation, error) {
	var out []detection.EndpointObservation
	cursor := ""
	for {
		page, err := s.assets.ListEndpoints(ctx, endpointrepo.ListFilter{
			AssetID: assetID, Pagination: pagination.Params{Limit: pagination.MaxLimit, Cursor: cursor},
		})
		if err != nil {
			return nil, fmt.Errorf("listing endpoints: %w", err)
		}
		for _, e := range page.Items {
			params, err := s.assets.ListEndpointParameters(ctx, e.ID)
			if err != nil {
				return nil, fmt.Errorf("listing endpoint parameters: %w", err)
			}
			names := make([]string, len(params))
			for i, p := range params {
				names[i] = p.Name
			}
			statusCode := 0
			if e.StatusCode != nil {
				statusCode = *e.StatusCode
			}
			out = append(out, detection.EndpointObservation{
				ID: e.ID, AssetID: e.AssetID, URL: e.URL, Method: string(e.Method), Path: e.Path,
				StatusCode: statusCode, ContentType: e.ContentType, Classification: string(e.Classification),
				APIType: e.APIType, APIVersion: e.APIVersion, Documented: e.Documented, Observed: e.Observed,
				Inferred: e.Inferred, Metadata: e.Metadata, Parameters: names,
			})
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	return out, nil
}

func (s *Service) loadFingerprints(ctx context.Context, assetID uuid.UUID) ([]detection.FingerprintObservation, error) {
	page, err := s.fingerprints.List(ctx, fingerprintrepo.ListFilter{
		AssetID: assetID, Status: domainfp.StatusActive, Pagination: pagination.Params{Limit: pagination.MaxLimit},
	})
	if err != nil {
		return nil, fmt.Errorf("listing fingerprints: %w", err)
	}
	out := make([]detection.FingerprintObservation, len(page.Items))
	for i, f := range page.Items {
		out[i] = detection.FingerprintObservation{
			Category: string(f.Category), Technology: f.Technology, Vendor: f.Vendor,
			Version: f.Version, Confidence: float64(f.Confidence),
		}
	}
	return out, nil
}

// convertServiceObservations splits a host's PORT/SERVICE assets into
// Phase 8's TLS and Service observation shapes, reading the metadata
// keys internal/discovery/service/network.go's buildNetworkMetadata
// writes.
func convertServiceObservations(assets []domainasset.Asset) ([]detection.TLSObservation, []detection.ServiceObservation) {
	var tls []detection.TLSObservation
	var services []detection.ServiceObservation
	for _, a := range assets {
		host := domainasset.StringField(a.Hostname)
		if host == "" {
			host = domainasset.StringField(a.IP)
		}
		port := 0
		if a.Port != nil {
			port = *a.Port
		}
		state, _ := a.Metadata["state"].(string)
		serviceName, _ := a.Metadata["service"].(string)
		protocol, _ := a.Metadata["protocol"].(string)
		services = append(services, detection.ServiceObservation{Host: host, Port: port, Protocol: protocol, State: state, Service: serviceName})

		version, hasVersion := a.Metadata["tls_version"].(string)
		if !hasVersion {
			continue
		}
		cipher, _ := a.Metadata["tls_cipher_suite"].(string)
		subject, _ := a.Metadata["certificate_subject"].(string)
		issuer, _ := a.Metadata["certificate_issuer"].(string)
		var notAfter time.Time
		if raw, ok := a.Metadata["certificate_not_after"].(string); ok {
			if t, err := time.Parse(time.RFC3339, raw); err == nil {
				notAfter = t
			}
		}
		tls = append(tls, detection.TLSObservation{
			Host: host, Port: port, Version: version, CipherSuite: cipher,
			Subject: subject, Issuer: issuer, NotAfter: notAfter,
		})
	}
	return tls, services
}

// persistFinding upserts f (converted to the domain model) plus its
// evidence in one transaction, then — as a best-effort follow-up, logged
// rather than aborting the run on failure, the same partial-persistence
// discipline every other phase applies (phase8.md §82/§83) — transitions
// its lifecycle Status and records the corresponding Event. Returns the
// persisted finding and, if a lifecycle-relevant Change occurred, that
// Change.
func (s *Service) persistFinding(ctx context.Context, f detection.Finding, targetID, scanID uuid.UUID) (domainfinding.Finding, *Change, error) {
	domainF := toDomainFinding(f, targetID, scanID)
	if err := domainF.Validate(); err != nil {
		return domainfinding.Finding{}, nil, apperrors.NewValidation("invalid finding", err)
	}

	var upserted domainfinding.Finding
	var created bool
	err := s.pool.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		txRepo := findingrepo.NewPostgresRepository(tx)

		result, wasCreated, upsertErr := txRepo.Upsert(ctx, domainF)
		if upsertErr != nil {
			return upsertErr
		}
		upserted = result
		created = wasCreated

		for _, ev := range f.Evidence {
			evidence := domainfinding.Evidence{
				FindingID: upserted.ID, Source: string(ev.Type), EvidenceType: mapEvidenceType(ev.Type),
				EvidenceData: domainasset.SanitizeMetadata(ev.Data), Confidence: domainfinding.Confidence(ev.Confidence),
				ObservedAt: domainF.LastSeen,
			}
			if err := evidence.Validate(); err != nil {
				return apperrors.NewValidation("invalid finding evidence", err)
			}
			if _, _, err := txRepo.CreateEvidence(ctx, evidence); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return domainfinding.Finding{}, nil, err
	}

	// upserted.Status reflects the PREVIOUS status (Upsert never touches
	// it — see internal/repository/finding.Repository.Upsert's doc
	// comment) for an existing row, or the just-inserted default (open)
	// for a brand new one — either way, exactly the "previous status"
	// NextStatus/ClassifyChange need.
	previous := detection.Status(upserted.Status)
	next := detection.NextStatus(previous, true)
	changeType, hasChange := detection.ClassifyChange(previous, true, created)

	var change *Change
	if domainfinding.Status(next) != upserted.Status {
		transitioned, err := s.findings.UpdateStatus(ctx, upserted.ID, domainfinding.Status(next), "")
		if err != nil {
			s.logger.Error("finding_status_transition_failed", "finding_id", upserted.ID, "error", err)
		} else {
			upserted = transitioned
		}
		s.recordEvent(ctx, upserted.ID, &scanID, eventTypeFor(changeType), domainfinding.Status(previous), upserted.Status, upserted.Severity, upserted.Confidence, "")
	}
	if hasChange {
		change = &Change{
			FindingID: upserted.ID, IdentityKey: upserted.IdentityKey, Title: upserted.Title,
			AssetID: upserted.AssetID, EndpointID: upserted.EndpointID, Type: changeType, DetectedAt: time.Now().UTC(),
		}
	}

	return upserted, change, nil
}

func eventTypeFor(change detection.ChangeType) domainfinding.EventType {
	switch change {
	case detection.ChangeNew:
		return domainfinding.EventOpened
	case detection.ChangeReopened:
		return domainfinding.EventReopened
	case detection.ChangeResolved:
		return domainfinding.EventResolved
	default:
		return domainfinding.EventUpdated
	}
}

// recordEvent writes one best-effort lifecycle audit row — a failure here
// is logged, never propagated, since the finding's own row (the
// authoritative current state) is already durably persisted by this
// point (phase8.md §71/§85).
func (s *Service) recordEvent(ctx context.Context, findingID uuid.UUID, scanID *uuid.UUID, eventType domainfinding.EventType, from, to domainfinding.Status, severity domainfinding.Severity, confidence domainfinding.Confidence, reason string) {
	e := domainfinding.Event{
		FindingID: findingID, ScanID: scanID, Type: eventType, FromStatus: from, ToStatus: to,
		Severity: severity, Confidence: confidence, Reason: reason, DetectedAt: time.Now().UTC(),
	}
	if err := e.Validate(); err != nil {
		s.logger.Error("finding_event_invalid", "finding_id", findingID, "error", err)
		return
	}
	if _, err := s.events.CreateEvent(ctx, e); err != nil {
		s.logger.Error("finding_event_persist_failed", "finding_id", findingID, "error", err)
	}
}

func toDomainFinding(f detection.Finding, targetID, scanID uuid.UUID) domainfinding.Finding {
	now := time.Now().UTC()
	scan := scanID
	references := make([]domainfinding.Reference, len(f.References))
	for i, r := range f.References {
		references[i] = domainfinding.Reference{Label: r.Label, URL: r.URL}
	}
	return domainfinding.Finding{
		TargetID: targetID, AssetID: f.AssetID, EndpointID: f.EndpointID, ScanID: &scan,
		DetectorID: f.DetectorID, DetectorVersion: f.DetectorVersion, Title: f.Title, Description: f.Description,
		Category: domainfinding.Category(f.Category), Scope: domainfinding.Scope(f.Scope),
		Severity: domainfinding.Severity(f.Severity), DetectorSeverity: domainfinding.Severity(f.Severity),
		Confidence: domainfinding.Confidence(f.Confidence), Status: domainfinding.StatusOpen,
		IdentityKey: domainfinding.IdentityKey(targetID, f.AssetID, f.EndpointID, f.DetectorID),
		Remediation: f.Remediation, References: references, Metadata: domainasset.SanitizeMetadata(f.Metadata),
		FirstSeen: now, LastSeen: now,
	}
}

func mapEvidenceType(t detection.EvidenceType) domainfinding.EvidenceType {
	mapped := domainfinding.EvidenceType(t)
	if mapped.Valid() {
		return mapped
	}
	return domainfinding.EvidenceConfiguration
}
