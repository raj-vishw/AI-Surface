package fingerprint

import (
	"context"
	"net/url"

	fpengine "ai-surface-platform/internal/fingerprint"

	domainasset "ai-surface-platform/internal/domain/asset"
	assetrepo "ai-surface-platform/internal/repository/asset"
	endpointrepo "ai-surface-platform/internal/repository/endpoint"
	"ai-surface-platform/internal/repository/pagination"
)

// buildObservation assembles a fpengine.Observation for asset entirely
// from data Phase 3/4/5 already persisted — Asset.Metadata's "latest
// snapshot" (see docs/architecture/dns-discovery.md and http-discovery.md
// for that convention), this asset's own discovered Endpoint path(s), and
// — because DNS/network/HTTP observations for one logical hostname live
// on separate sibling Asset rows, not one combined row (phase6.md §25's
// pipeline diagram: DNS + Network + HTTP observations all feed one
// fingerprinting stage) — every sibling asset sharing the same
// (TargetID, Hostname). Never performs a fresh network/DNS request
// (phase6.md §46).
func (s *Service) buildObservation(ctx context.Context, asset domainasset.Asset) (fpengine.Observation, error) {
	obs := fpengine.Observation{
		AssetID:     asset.ID.String(),
		Hostname:    domainasset.StringField(asset.Hostname),
		URL:         domainasset.StringField(asset.URL),
		Port:        asset.Port,
		Service:     domainasset.StringField(asset.Technology),
		ContentType: "",
		ObservedAt:  asset.LastSeen,
	}
	if asset.URL != nil {
		if u, err := url.Parse(*asset.URL); err == nil {
			obs.URLPath = u.Path
		}
	}

	applyMetadata(&obs, asset.Metadata)

	if obs.Hostname != "" {
		siblings, err := s.assets.List(ctx, assetrepo.ListFilter{
			TargetID: asset.TargetID, Hostname: obs.Hostname,
			Pagination: pagination.Params{Limit: pagination.MaxLimit},
		})
		if err != nil {
			return fpengine.Observation{}, err
		}
		for _, sib := range siblings.Items {
			if sib.ID == asset.ID {
				continue
			}
			if obs.Service == "" {
				obs.Service = domainasset.StringField(sib.Technology)
			}
			if obs.Port == nil {
				obs.Port = sib.Port
			}
			applyMetadata(&obs, sib.Metadata)
		}
	}

	endpoints, err := s.assets.ListEndpoints(ctx, endpointrepo.ListFilter{
		AssetID: asset.ID, Pagination: pagination.Params{Limit: pagination.MaxLimit},
	})
	if err != nil {
		return fpengine.Observation{}, err
	}
	for _, e := range endpoints.Items {
		obs.APIPaths = append(obs.APIPaths, e.Path)
		if obs.ContentType == "" {
			obs.ContentType = e.ContentType
		}
		if e.ResponseHash != "" && obs.ResponseHash == "" {
			obs.ResponseHash = e.ResponseHash
		}
	}

	return obs, nil
}

// applyMetadata folds one asset's latest-snapshot Metadata into obs,
// never overwriting a field obs already has (first asset examined wins —
// callers apply the asset under analysis first, then its siblings, so
// its own direct observations always take precedence over a sibling's).
func applyMetadata(obs *fpengine.Observation, metadata map[string]any) {
	if metadata == nil {
		return
	}

	// HTTP metadata (internal/discovery/service/discovery.go's
	// buildMetadata / this package's Phase 3 header-capture extension).
	if obs.Headers == nil {
		obs.Headers = map[string]string{}
	}
	if headers, ok := metadata["headers"].(map[string]any); ok {
		for k, v := range headers {
			if _, exists := obs.Headers[k]; !exists {
				if s, ok := v.(string); ok {
					obs.Headers[k] = s
				}
			}
		}
	}
	if server, ok := metadata["server"].(string); ok && server != "" {
		if _, exists := obs.Headers["Server"]; !exists {
			obs.Headers["Server"] = server
		}
	}
	if obs.ContentType == "" {
		if ct, ok := metadata["content_type"].(string); ok {
			obs.ContentType = ct
		}
	}
	if obs.ResponseHash == "" {
		if h, ok := metadata["response_hash"].(string); ok {
			obs.ResponseHash = h
		}
	}
	if len(obs.CookieNames) == 0 {
		if names, ok := metadata["cookie_names"].([]any); ok {
			for _, n := range names {
				if s, ok := n.(string); ok {
					obs.CookieNames = append(obs.CookieNames, s)
				}
			}
		}
	}
	if obs.TLSVersion == "" {
		if v, ok := metadata["tls_version"].(string); ok {
			obs.TLSVersion = v
		}
	}
	if obs.TLSCipherSuite == "" {
		if v, ok := metadata["tls_cipher_suite"].(string); ok {
			obs.TLSCipherSuite = v
		}
	}
	if obs.CertificateSubject == "" {
		if v, ok := metadata["certificate_subject"].(string); ok {
			obs.CertificateSubject = v
		}
	}
	if obs.CertificateIssuer == "" {
		if v, ok := metadata["certificate_issuer"].(string); ok {
			obs.CertificateIssuer = v
		}
	}
	if obs.Service == "" {
		if v, ok := metadata["service"].(string); ok {
			obs.Service = v
		}
	}

	// DNS metadata (internal/discovery/service/dns.go's buildHostMetadata).
	if v, ok := metadata["a_records"].([]any); ok {
		for _, r := range v {
			if s, ok := r.(string); ok {
				obs.DNSRecords = append(obs.DNSRecords, fpengine.DNSRecordObservation{Type: "A", Value: s})
			}
		}
	}
	if v, ok := metadata["aaaa_records"].([]any); ok {
		for _, r := range v {
			if s, ok := r.(string); ok {
				obs.DNSRecords = append(obs.DNSRecords, fpengine.DNSRecordObservation{Type: "AAAA", Value: s})
			}
		}
	}
	if v, ok := metadata["cname_target"].(string); ok && v != "" {
		obs.DNSRecords = append(obs.DNSRecords, fpengine.DNSRecordObservation{Type: "CNAME", Value: v})
	}
	if v, ok := metadata["ns_records"].([]any); ok {
		for _, r := range v {
			if s, ok := r.(string); ok {
				obs.DNSRecords = append(obs.DNSRecords, fpengine.DNSRecordObservation{Type: "NS", Value: s})
			}
		}
	}
}
