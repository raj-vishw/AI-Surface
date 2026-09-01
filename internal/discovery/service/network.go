// Package service orchestrates discovery end-to-end. This file adds
// network discovery orchestration to the same package as HTTP discovery's
// (discovery.go) rather than a parallel package — Phase 4 integrates into
// the discovery architecture Phase 3 established (same Service, same
// TargetService/AssetService, same
// authorization -> scope -> scan -> persist shape) instead of duplicating
// it (phase4.md §3).
package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	discoverynet "ai-recon-platform/internal/discovery/network"
	domainasset "ai-recon-platform/internal/domain/asset"
	domaintarget "ai-recon-platform/internal/domain/target"
	apperrors "ai-recon-platform/internal/errors"
	assetsvc "ai-recon-platform/internal/service/asset"
)

// networkSource is network discovery's fixed evidence/asset Source
// attribution (internal/domain/asset's Source vocabulary, phase2.md §12) —
// distinct from HTTP discovery's "http" so the two are always
// distinguishable in the persisted inventory even though (per phase4.md
// §43) they may describe the very same logical asset.
const networkSource = "network"

// networkExistenceConfidence is lower than HTTP discovery's 0.9
// (existenceConfidence in discovery.go): a bare TCP connect confirms the
// port is reachable, not that any particular application is actually
// serving meaningful content there — weaker evidence than a completed
// HTTP response.
const networkExistenceConfidence = domainasset.Confidence(0.7)

// supportedNetworkTargetTypes are the target types network discovery
// accepts (phase4.md §10).
var supportedNetworkTargetTypes = map[domaintarget.Type]bool{
	domaintarget.TypeHost: true,
	domaintarget.TypeIP:   true,
	domaintarget.TypeCIDR: true,
}

// NetworkRequest describes one `ai-recon network-scan` invocation.
type NetworkRequest struct {
	// TargetType/TargetValue identify an existing, already-authorized
	// target (phase4.md §12) — RunNetwork never creates or authorizes a
	// target itself.
	TargetType  domaintarget.Type
	TargetValue string
	// Profile selects a named port set from Config.Profiles; if empty,
	// PortsSpec (raw --ports syntax, see network.ParsePorts) is used
	// instead. Exactly one of the two must be non-empty.
	Profile   string
	PortsSpec string
	DryRun    bool
	Config    discoverynet.Config
}

// NetworkDryRunReport is returned instead of a Summary when req.DryRun is
// true — no TCP connection is made and nothing is persisted (phase4.md
// §19).
type NetworkDryRunReport struct {
	Target string
	Hosts  []string
	Ports  []int
}

// RunNetwork loads and authorizes req's target, expands it to concrete
// host addresses (phase4.md §11), and either reports what would be
// scanned (NetworkDryRunReport) or executes TCP connect discovery and
// persists every OPEN result through AssetService (*network.Summary).
// Exactly one of the two return values is non-nil on success.
func (s *Service) RunNetwork(ctx context.Context, req NetworkRequest) (*discoverynet.Summary, *NetworkDryRunReport, error) {
	if !supportedNetworkTargetTypes[req.TargetType] {
		return nil, nil, apperrors.NewValidation(
			fmt.Sprintf("target type %s is not supported by network discovery (only HOST, IP, CIDR)", req.TargetType), nil)
	}

	target, err := s.targets.GetByValue(ctx, req.TargetType, req.TargetValue)
	if err != nil {
		return nil, nil, fmt.Errorf("loading target: %w", err)
	}
	if err := target.Validate(); err != nil {
		return nil, nil, fmt.Errorf("target is invalid: %w", err)
	}
	// Authorization is checked entirely from the already-loaded Target —
	// no TCP connection is made merely to determine whether it exists
	// (phase4.md §12).
	if !target.IsAuthorized() {
		return nil, nil, apperrors.NewForbidden("target is not authorized for active discovery", nil)
	}

	ports, err := resolveNetworkPorts(req)
	if err != nil {
		return nil, nil, err
	}

	hosts, err := discoverynet.ExpandTarget(req.TargetType, req.TargetValue, req.Config.MaxHosts)
	if err != nil {
		return nil, nil, err
	}

	scope, err := discoverynet.NewScopeChecker(req.TargetType, req.TargetValue)
	if err != nil {
		return nil, nil, err
	}

	// Defense in depth, the same discipline HTTP discovery's candidate
	// generation applies (phase3.md §11): every expanded host is checked
	// against scope before it is even offered to the scanner, which
	// re-checks per attempt regardless (phase4.md §13).
	var inScopeHosts []string
	for _, h := range hosts {
		if scope.Allowed(h) {
			inScopeHosts = append(inScopeHosts, h)
		}
	}

	if req.DryRun {
		return nil, &NetworkDryRunReport{Target: req.TargetValue, Hosts: inScopeHosts, Ports: ports}, nil
	}

	scanner := discoverynet.NewScanner(s.logger, req.Config)
	summary, err := scanner.Scan(ctx, discoverynet.ScanRequest{
		TargetID: target.ID, Target: req.TargetValue, Hosts: inScopeHosts, Ports: ports,
	}, scope)
	if err != nil {
		return nil, nil, err
	}

	for _, result := range summary.Results {
		if !result.Succeeded() {
			continue
		}
		// A persistence failure for one port must not abort the scan
		// (phase4.md §46) — the TCP observation itself already completed;
		// log and move on to the next result.
		if err := s.persistPort(ctx, target.ID, result); err != nil {
			s.logger.Error("network_discovery_persist_failed",
				"scan_id", result.ScanID, "target_id", target.ID, "host", result.Host, "port", result.Port, "error", err)
		}
	}

	return summary, nil, nil
}

func resolveNetworkPorts(req NetworkRequest) ([]int, error) {
	if req.Profile != "" {
		ports, err := req.Config.ResolvePorts(req.Profile)
		if err != nil {
			return nil, err
		}
		return ports, nil
	}
	if req.PortsSpec == "" {
		return nil, apperrors.NewValidation("either --ports or --profile must be given", nil)
	}
	return discoverynet.ParsePorts(req.PortsSpec)
}

// persistPort normalizes result into a Phase 2 Asset (type PORT — see
// internal/domain/asset) with PORT_OBSERVATION evidence recorded
// atomically alongside it (AssetService.RecordObservation). It reuses
// Phase 2's identity/deduplication/redaction logic entirely — the
// identity is host+port+protocol via asset.Identity's existing portTypes
// handling, computed by AssetService exactly as for any other PORT/
// SERVICE asset (phase4.md §25/§26); this function computes no identity
// or SQL of its own.
func (s *Service) persistPort(ctx context.Context, targetID uuid.UUID, result discoverynet.PortResult) error {
	host := result.Host
	port := result.Port
	protocol := result.Protocol

	var technology *string
	if result.Service != discoverynet.ServiceUnknown {
		t := string(result.Service)
		technology = &t
	}

	metadata := buildNetworkMetadata(result, true)
	evidenceData := buildNetworkMetadata(result, false)

	_, _, err := s.assets.RecordObservation(ctx, assetsvc.ObservationInput{
		Asset: assetsvc.Input{
			TargetID:   targetID,
			Type:       domainasset.TypePort,
			Hostname:   &host,
			Port:       &port,
			Protocol:   &protocol,
			Technology: technology,
			Source:     networkSource,
			Confidence: networkExistenceConfidence,
			Metadata:   metadata,
			ObservedAt: result.ObservedAt,
		},
		EvidenceType: domainasset.EvidencePortObservation,
		EvidenceData: evidenceData,
	})
	if err != nil {
		return fmt.Errorf("recording asset observation: %w", err)
	}
	return nil
}

// buildNetworkMetadata assembles the (pre-redaction) metadata attached to
// the asset row and, when includeScanID is false, the evidence record.
// includeScanID excludes "scan_id" from evidence data for the same reason
// discovery.go's buildMetadata does for HTTP evidence: Phase 2's evidence
// deduplication fingerprints this map, and scan_id is unique per run by
// design (see discovery.go's doc comment — this was a real bug found and
// fixed during Phase 3's manual verification; Phase 4 applies the same
// fix from the start).
func buildNetworkMetadata(result discoverynet.PortResult, includeScanID bool) map[string]any {
	metadata := map[string]any{
		"host":                 result.Host,
		"port":                 result.Port,
		"protocol":             result.Protocol,
		"state":                string(result.State),
		"duration_ms":          result.Duration.Milliseconds(),
		"service":              string(result.Service),
		"http_candidate":       result.HTTPCandidate,
		"ai_service_candidate": result.AIServiceCandidate,
		"discovery_method":     "network",
	}
	if includeScanID {
		metadata["scan_id"] = result.ScanID.String()
	}
	if result.CandidateReason != "" {
		metadata["candidate_reason"] = result.CandidateReason
	}
	if len(result.Indicators) > 0 {
		indicators := make([]any, len(result.Indicators))
		for i, v := range result.Indicators {
			indicators[i] = v
		}
		metadata["indicators"] = indicators
	}
	if result.TLSMetadata != nil {
		metadata["tls_version"] = result.TLSMetadata.Version
		metadata["tls_cipher_suite"] = result.TLSMetadata.CipherSuite
		if result.TLSMetadata.Subject != "" {
			metadata["certificate_subject"] = result.TLSMetadata.Subject
		}
		if result.TLSMetadata.Issuer != "" {
			metadata["certificate_issuer"] = result.TLSMetadata.Issuer
		}
	}
	return metadata
}
