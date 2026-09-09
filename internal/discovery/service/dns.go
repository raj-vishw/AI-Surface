// Package service orchestrates discovery end-to-end. This file adds DNS
// discovery orchestration to the same package as HTTP's (discovery.go)
// and network's (network.go) — Phase 5 integrates into the discovery
// architecture Phase 3/4 established (same Service, same TargetService/
// AssetService, same authorization -> scope -> scan -> persist shape)
// instead of duplicating it (phase5.md §4).
package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	discoverydns "ai-surface-platform/internal/discovery/dns"
	discoveryhttp "ai-surface-platform/internal/discovery/http"
	domainasset "ai-surface-platform/internal/domain/asset"
	domaintarget "ai-surface-platform/internal/domain/target"
	apperrors "ai-surface-platform/internal/errors"
	assetsvc "ai-surface-platform/internal/service/asset"
)

// dnsSource is DNS discovery's fixed evidence/asset Source attribution
// (internal/domain/asset's Source vocabulary, phase2.md §12) — distinct
// from HTTP's "http" and network's "network".
const dnsSource = "dns"

// hostnameExistenceConfidence is the Asset.Confidence recorded for a
// DOMAIN/SUBDOMAIN asset backed by at least one resolved DNS record —
// lower than HTTP discovery's 0.9 (a DNS answer confirms the name exists
// and points somewhere, not that any application is listening there), on
// par with network discovery's bare-TCP-reachability confidence.
const hostnameExistenceConfidence = domainasset.Confidence(0.7)

// ipExistenceConfidence is the confidence recorded for an IP asset
// derived from an A/AAAA record — the address is confirmed to be what a
// name currently resolves to, not confirmed reachable (no connection is
// attempted here; that's Phase 4's job, run separately).
const ipExistenceConfidence = domainasset.Confidence(0.6)

// supportedDNSTargetTypes are the target types DNS discovery accepts
// (phase5.md implies DOMAIN — the target being enumerated — analogous to
// Phase 3's URL/HOST/DOMAIN and Phase 4's HOST/IP/CIDR).
var supportedDNSTargetTypes = map[domaintarget.Type]bool{
	domaintarget.TypeDomain: true,
	domaintarget.TypeHost:   true,
}

// DNSRequest describes one `ai-surface dns-scan` (or `subdomain-scan`)
// invocation.
type DNSRequest struct {
	// TargetType/TargetValue identify an existing, already-authorized
	// target (phase5.md §42) — RunDNS never creates or authorizes a
	// target itself.
	TargetType  domaintarget.Type
	TargetValue string
	// Profile selects a named record-type + subdomain-word set from
	// Config.Profiles; empty uses Config.RecordTypes / Config.Subdomains
	// directly.
	Profile string
	// RecordTypesOverride, if non-empty, overrides the profile's/config's
	// record types entirely (the CLI's --record-types flag).
	RecordTypesOverride []discoverydns.RecordType
	// MaxDepthOverride, if non-nil, overrides the profile's/config's
	// subdomain depth (the CLI's --max-depth flag) — an explicit flag
	// always wins over a profile default, the same precedence every other
	// layered setting in this project follows.
	MaxDepthOverride *int
	// EnumerateSubdomains controls whether subdomain enumeration runs at
	// all — DNS record discovery and subdomain discovery are kept
	// conceptually distinct (phase5.md §1); a caller may want only one.
	EnumerateSubdomains bool
	WordlistPath        string
	DryRun              bool
	Config              discoverydns.Config
}

// DNSDryRunReport is returned instead of a Summary when req.DryRun is
// true — no DNS query is made and nothing is persisted (phase5.md §53).
type DNSDryRunReport struct {
	Target              string
	RecordTypes         []discoverydns.RecordType
	SubdomainCandidates []string
}

// RunDNS loads and authorizes req's target, then either reports what
// would be queried (DNSDryRunReport) or executes DNS discovery and
// persists every meaningful result through AssetService
// (*discoverydns.Summary). Exactly one of the two return values is
// non-nil on success.
func (s *Service) RunDNS(ctx context.Context, req DNSRequest) (*discoverydns.Summary, *DNSDryRunReport, error) {
	if !supportedDNSTargetTypes[req.TargetType] {
		return nil, nil, apperrors.NewValidation(
			fmt.Sprintf("target type %s is not supported by DNS discovery (only DOMAIN, HOST)", req.TargetType), nil)
	}

	target, err := s.targets.GetByValue(ctx, req.TargetType, req.TargetValue)
	if err != nil {
		return nil, nil, fmt.Errorf("loading target: %w", err)
	}
	if err := target.Validate(); err != nil {
		return nil, nil, fmt.Errorf("target is invalid: %w", err)
	}
	// Authorization is checked entirely from the already-loaded Target —
	// no DNS query is made merely to determine whether it exists
	// (phase5.md §42).
	if !target.IsAuthorized() {
		return nil, nil, apperrors.NewForbidden("target is not authorized for active discovery", nil)
	}

	recordTypes, profileWords, maxDepth, err := req.Config.ResolveProfile(req.Profile)
	if err != nil {
		return nil, nil, err
	}
	if len(req.RecordTypesOverride) > 0 {
		recordTypes = req.RecordTypesOverride
	}
	if req.MaxDepthOverride != nil {
		maxDepth = *req.MaxDepthOverride
	}
	// req.Config is a value (not a pointer) copy of the caller's config,
	// so mutating it here to fold in the resolved depth is local to this
	// call — it never affects the caller's original Config.
	req.Config.Subdomains.MaxDepth = maxDepth

	var subdomainWords []string
	if req.EnumerateSubdomains {
		if req.WordlistPath != "" {
			subdomainWords, err = discoverydns.LoadWordlist(req.WordlistPath)
		} else if len(profileWords) > 0 {
			subdomainWords = profileWords
		} else {
			subdomainWords = req.Config.Subdomains.Words
		}
		if err != nil {
			return nil, nil, err
		}
	}

	scope, err := discoveryhttp.NewScopeValidator(dnsScopeSeedURL(req.TargetValue))
	if err != nil {
		return nil, nil, fmt.Errorf("building scope validator: %w", err)
	}

	if req.DryRun {
		report := &DNSDryRunReport{Target: req.TargetValue, RecordTypes: recordTypes}
		if len(subdomainWords) > 0 {
			candidates, err := discoverydns.GenerateCandidates(req.TargetValue, subdomainWords, maxDepth, req.Config.Subdomains.MaxCandidates)
			if err != nil {
				return nil, nil, err
			}
			for _, c := range candidates {
				report.SubdomainCandidates = append(report.SubdomainCandidates, c.Name)
			}
		}
		return nil, report, nil
	}

	resolver, err := buildResolver(req.Config)
	if err != nil {
		return nil, nil, fmt.Errorf("building DNS resolver: %w", err)
	}

	scanner := discoverydns.NewScanner(resolver, s.logger, req.Config)
	summary, err := scanner.Scan(ctx, discoverydns.ScanRequest{
		TargetID: target.ID, Domain: req.TargetValue, RecordTypes: recordTypes, SubdomainWords: subdomainWords,
	}, scope)
	if err != nil {
		return nil, nil, err
	}

	s.persistDNSSummary(ctx, target.ID, req.TargetValue, summary)

	return summary, nil, nil
}

func buildResolver(cfg discoverydns.Config) (discoverydns.Resolver, error) {
	if len(cfg.Resolvers) > 0 {
		return discoverydns.NewExplicitResolver(cfg.Resolvers, cfg.Timeout)
	}
	return discoverydns.NewSystemResolver(cfg.Timeout)
}

func dnsScopeSeedURL(domain string) string {
	return "https://" + domain
}

// persistDNSSummary normalizes every meaningful result into Phase 2
// assets/evidence. A persistence failure for one name must not abort the
// rest (phase5.md §46) — each is logged and the loop continues.
func (s *Service) persistDNSSummary(ctx context.Context, targetID uuid.UUID, domain string, summary *discoverydns.Summary) {
	// The target domain's own records (phase5.md §11-§18 apply to the
	// domain itself, not only discovered subdomains).
	var domainRecords []discoverydns.Record
	for _, r := range summary.RecordResults {
		if r.Type == discoverydns.TypePTR || r.Name != domain {
			continue
		}
		domainRecords = append(domainRecords, r.Records...)
	}
	if len(domainRecords) > 0 {
		if err := s.persistHostRecords(ctx, targetID, domain, domainasset.TypeDomain, domainRecords, summary.ScanID); err != nil {
			s.logger.Error("dns_discovery_persist_failed", "scan_id", summary.ScanID, "target_id", targetID, "name", domain, "error", err)
		}
	}

	// Discovered subdomains.
	for _, sd := range summary.SubdomainResults {
		if !sd.Succeeded() {
			continue
		}
		if err := s.persistHostRecords(ctx, targetID, sd.Name, domainasset.TypeSubdomain, sd.Records, summary.ScanID); err != nil {
			s.logger.Error("dns_discovery_persist_failed", "scan_id", summary.ScanID, "target_id", targetID, "name", sd.Name, "error", err)
		}
	}

	// Discovered IP addresses (phase5.md §32) — one per unique address
	// across every A/AAAA record seen (domain's own plus subdomains').
	for ip, hostname := range collectDiscoveredIPs(domain, domainRecords, summary.SubdomainResults) {
		if err := s.persistIP(ctx, targetID, ip, hostname, summary.ScanID); err != nil {
			s.logger.Error("dns_discovery_persist_failed", "scan_id", summary.ScanID, "target_id", targetID, "ip", ip, "error", err)
		}
	}

	// PTR results (phase5.md §19) — recorded as evidence on the IP asset
	// they were looked up for, if that asset was persisted above.
	for _, r := range summary.RecordResults {
		if r.Type != discoverydns.TypePTR || r.State != discoverydns.StateResolved {
			continue
		}
		if err := s.persistPTR(ctx, targetID, r.Name, r.Records, summary.ScanID); err != nil {
			s.logger.Error("dns_discovery_persist_failed", "scan_id", summary.ScanID, "target_id", targetID, "ip", r.Name, "error", err)
		}
	}
}

// persistHostRecords upserts a DOMAIN/SUBDOMAIN asset for hostname and
// records one DNS_RECORD evidence entry per record (phase5.md §32/§35).
// Records of every type observed for hostname in this scan are folded
// into one metadata snapshot; each individual record still gets its own
// immutable evidence entry (phase5.md §38 — multiple A records are never
// collapsed into one).
func (s *Service) persistHostRecords(ctx context.Context, targetID uuid.UUID, hostname string, assetType domainasset.Type, records []discoverydns.Record, scanID uuid.UUID) error {
	if len(records) == 0 {
		return nil
	}
	metadata := buildHostMetadata(records, scanID, true)

	for _, record := range records {
		evidenceData := recordEvidenceData(record) // no scan_id, no ttl — see buildHostMetadata's doc comment for why

		_, _, err := s.assets.RecordObservation(ctx, assetsvc.ObservationInput{
			Asset: assetsvc.Input{
				TargetID:   targetID,
				Type:       assetType,
				Hostname:   &hostname,
				Source:     dnsSource,
				Confidence: hostnameExistenceConfidence,
				Metadata:   metadata,
			},
			EvidenceType: domainasset.EvidenceDNSRecord,
			EvidenceData: evidenceData,
		})
		if err != nil {
			return fmt.Errorf("recording DNS observation for %s (%s %s): %w", hostname, record.Type, record.Value, err)
		}
	}
	return nil
}

// persistIP upserts an IP asset for a discovered A/AAAA address.
func (s *Service) persistIP(ctx context.Context, targetID uuid.UUID, ip, resolvedFrom string, scanID uuid.UUID) error {
	metadata := map[string]any{
		"discovery_method": "dns",
		"resolved_from":    resolvedFrom,
		"scan_id":          scanID.String(),
	}
	evidenceData := map[string]any{
		"discovery_method": "dns",
		"resolved_from":    resolvedFrom,
		"record_type":      "A/AAAA",
	}

	ipCopy := ip
	_, _, err := s.assets.RecordObservation(ctx, assetsvc.ObservationInput{
		Asset: assetsvc.Input{
			TargetID:   targetID,
			Type:       domainasset.TypeIP,
			IP:         &ipCopy,
			Source:     dnsSource,
			Confidence: ipExistenceConfidence,
			Metadata:   metadata,
		},
		EvidenceType: domainasset.EvidenceDNSRecord,
		EvidenceData: evidenceData,
	})
	if err != nil {
		return fmt.Errorf("recording IP observation for %s: %w", ip, err)
	}
	return nil
}

// persistPTR records a PTR result as evidence on the IP asset it was
// looked up for. Like persistIP, this goes through RecordObservation's
// upsert — idempotent against whatever asset persistIP already created
// for the same address in this same scan (or a prior one); if no A/AAAA
// observation ever created that IP asset, a standalone PTR result is
// still legitimate evidence the address exists and is worth an asset of
// its own.
func (s *Service) persistPTR(ctx context.Context, targetID uuid.UUID, ip string, records []discoverydns.Record, scanID uuid.UUID) error {
	for _, record := range records {
		metadata := map[string]any{
			"discovery_method": "dns", "ptr_name": record.Value, "scan_id": scanID.String(),
		}
		evidenceData := recordEvidenceData(record)

		ipCopy := ip
		_, _, err := s.assets.RecordObservation(ctx, assetsvc.ObservationInput{
			Asset: assetsvc.Input{
				TargetID:   targetID,
				Type:       domainasset.TypeIP,
				IP:         &ipCopy,
				Source:     dnsSource,
				Confidence: ipExistenceConfidence,
				Metadata:   metadata,
			},
			EvidenceType: domainasset.EvidenceDNSRecord,
			EvidenceData: evidenceData,
		})
		if err != nil {
			return fmt.Errorf("recording PTR observation for %s: %w", ip, err)
		}
	}
	return nil
}

// collectDiscoveredIPs gathers every unique A/AAAA address seen across
// domainRecords (the target domain's own records) and every succeeded
// subdomain result, mapped to the hostname it was resolved from. When the
// same address is seen for more than one hostname in this scan, whichever
// is encountered first wins — Phase 2's metadata merge can't accumulate a
// list across separate upserts (phase2.md's JSONB `||` merge replaces a
// key, it doesn't append to an array), so "resolved_from" is always a
// latest/one-of snapshot; the full history lives in evidence, not
// metadata (see buildHostMetadata's doc comment).
func collectDiscoveredIPs(domain string, domainRecords []discoverydns.Record, subdomains []discoverydns.SubdomainResult) map[string]string {
	ips := make(map[string]string)
	add := func(hostname string, records []discoverydns.Record) {
		for _, r := range records {
			if r.Type != discoverydns.TypeA && r.Type != discoverydns.TypeAAAA {
				continue
			}
			if _, exists := ips[r.Value]; !exists {
				ips[r.Value] = hostname
			}
		}
	}
	add(domain, domainRecords)
	for _, sd := range subdomains {
		if sd.Succeeded() {
			add(sd.Name, sd.Records)
		}
	}
	return ips
}

// buildHostMetadata assembles the (pre-redaction — AssetService sanitizes
// it before anything is logged or stored) metadata attached to a DOMAIN/
// SUBDOMAIN asset row: a snapshot of every record type/value observed for
// hostname in this scan, folded together. This is always the *latest*
// snapshot — Phase 2's upsert metadata merge replaces keys, it doesn't
// preserve older values — which is why every individual record is also
// recorded as its own immutable evidence entry (buildHostMetadata's
// caller, persistHostRecords, does both): full historical DNS state lives
// in evidence, not in this snapshot (phase5.md §37: "do not erase ...
// simply because it is no longer current").
func buildHostMetadata(records []discoverydns.Record, scanID uuid.UUID, includeScanID bool) map[string]any {
	metadata := map[string]any{"discovery_method": "dns"}
	if includeScanID {
		metadata["scan_id"] = scanID.String()
	}

	var aRecords, aaaaRecords, nsRecords, txtRecords, mxRecords []any
	for _, r := range records {
		switch r.Type {
		case discoverydns.TypeA:
			aRecords = append(aRecords, r.Value)
		case discoverydns.TypeAAAA:
			aaaaRecords = append(aaaaRecords, r.Value)
		case discoverydns.TypeCNAME:
			metadata["cname_target"] = r.Value
		case discoverydns.TypeMX:
			priority := 0
			if r.Priority != nil {
				priority = *r.Priority
			}
			mxRecords = append(mxRecords, fmt.Sprintf("%d %s", priority, r.Value))
		case discoverydns.TypeNS:
			nsRecords = append(nsRecords, r.Value)
		case discoverydns.TypeTXT:
			txtRecords = append(txtRecords, r.Value)
		case discoverydns.TypeSOA:
			if r.SOA != nil {
				metadata["soa_primary_ns"] = r.SOA.PrimaryNS
				metadata["soa_serial"] = r.SOA.Serial
			}
		case discoverydns.TypeCAA:
			if r.CAA != nil {
				metadata["caa_tag"] = r.CAA.Tag
				metadata["caa_value"] = r.CAA.Value
			}
		case discoverydns.TypePTR:
			// PTR is handled by persistPTR against the IP asset, never
			// folded into a hostname's own metadata snapshot.
		}
	}
	if len(aRecords) > 0 {
		metadata["a_records"] = aRecords
	}
	if len(aaaaRecords) > 0 {
		metadata["aaaa_records"] = aaaaRecords
	}
	if len(mxRecords) > 0 {
		metadata["mx_records"] = mxRecords
	}
	if len(nsRecords) > 0 {
		metadata["ns_records"] = nsRecords
	}
	if len(txtRecords) > 0 {
		metadata["txt_records"] = txtRecords
	}
	return metadata
}

// recordEvidenceData builds one record's evidence payload — name, type,
// value, priority where applicable. TTL and scan_id are deliberately
// excluded from this map: Phase 2's evidence deduplication fingerprints
// exactly this map, and both TTL (which naturally fluctuates as a real
// resolver's cache counts it down — even when the underlying DNS answer
// hasn't changed at all) and scan_id (unique per run by design) would
// otherwise make every re-scan of an unchanged record create a brand-new
// evidence row forever. This is the same lesson Phase 3 learned the hard
// way (see docs/architecture/http-discovery.md) applied proactively here
// and in Phase 4.
func recordEvidenceData(r discoverydns.Record) map[string]any {
	data := map[string]any{
		"record_type": string(r.Type),
		"name":        r.Name,
		"value":       r.Value,
	}
	if r.Priority != nil {
		data["priority"] = *r.Priority
	}
	if r.SOA != nil {
		data["soa_primary_ns"] = r.SOA.PrimaryNS
		data["soa_mailbox"] = r.SOA.Mailbox
		data["soa_serial"] = r.SOA.Serial
		data["soa_refresh"] = r.SOA.Refresh
		data["soa_retry"] = r.SOA.Retry
		data["soa_expire"] = r.SOA.Expire
	}
	if r.CAA != nil {
		data["caa_flag"] = r.CAA.Flag
		data["caa_tag"] = r.CAA.Tag
		data["caa_value"] = r.CAA.Value
	}
	return data
}
