//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	discoverydns "ai-recon-platform/internal/discovery/dns"
	discoverysvc "ai-recon-platform/internal/discovery/service"
	domainasset "ai-recon-platform/internal/domain/asset"
	domaintarget "ai-recon-platform/internal/domain/target"
	assetrepo "ai-recon-platform/internal/repository/asset"
	assetsvc "ai-recon-platform/internal/service/asset"
	targetsvc "ai-recon-platform/internal/service/target"
	dnsfixture "ai-recon-platform/test/fixtures/dns"
)

// dnsTestConfig returns a small, fast DNS discovery configuration pointed
// at server — no public DNS dependency (phase5.md §57).
func dnsTestConfig(server *dnsfixture.Server) discoverydns.Config {
	return discoverydns.Config{
		Timeout:        2 * time.Second,
		MaxConcurrency: 10,
		Resolvers:      []string{server.Addr()},
		RecordTypes:    []discoverydns.RecordType{discoverydns.TypeA, discoverydns.TypeAAAA, discoverydns.TypeCNAME, discoverydns.TypeMX, discoverydns.TypeNS, discoverydns.TypeTXT, discoverydns.TypeSOA, discoverydns.TypeCAA},
		ReversePTR:     true,
		Subdomains:     discoverydns.SubdomainConfig{MaxCandidates: 100, MaxDepth: 1, WildcardDetection: true},
	}
}

func TestDNSPersistence_EndToEnd(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	server, err := dnsfixture.New()
	if err != nil {
		t.Fatalf("starting DNS fixture: %v", err)
	}
	defer func() { _ = server.Close() }()

	domainValue := uniqueDNSDomain("endtoend")
	if err := server.SetRecords(domainValue+".", dns.TypeA, domainValue+". 300 IN A 192.0.2.10"); err != nil {
		t.Fatalf("SetRecords A: %v", err)
	}
	if err := server.SetRecords("api."+domainValue+".", dns.TypeA, "api."+domainValue+". 300 IN A 192.0.2.20"); err != nil {
		t.Fatalf("SetRecords api A: %v", err)
	}

	target := getOrCreateAuthorizedDNSTarget(t, targets, domainValue)

	summary, dryRun, err := discovery.RunDNS(context.Background(), discoverysvc.DNSRequest{
		TargetType: domaintarget.TypeDomain, TargetValue: domainValue,
		EnumerateSubdomains: true, Config: dnsConfigWithWords(server, []string{"api", "missing"}),
	})
	if err != nil {
		t.Fatalf("RunDNS() failed: %v", err)
	}
	if dryRun != nil {
		t.Fatal("expected a real scan, not a dry-run report")
	}
	if summary.Resolved == 0 {
		t.Fatalf("expected at least one resolved record, got %+v", summary)
	}
	if summary.SubdomainsDiscovered != 1 {
		t.Errorf("SubdomainsDiscovered = %d, want 1 (api only; missing NXDOMAINs)", summary.SubdomainsDiscovered)
	}

	page, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}

	domainAsset := findByHostname(t, page.Items, domainValue)
	if domainAsset.Type != domainasset.TypeDomain {
		t.Errorf("asset.Type = %s, want %s", domainAsset.Type, domainasset.TypeDomain)
	}
	if domainAsset.Source != "dns" {
		t.Errorf("asset.Source = %q, want %q", domainAsset.Source, "dns")
	}

	subAsset := findByHostname(t, page.Items, "api."+domainValue)
	if subAsset.Type != domainasset.TypeSubdomain {
		t.Errorf("asset.Type = %s, want %s", subAsset.Type, domainasset.TypeSubdomain)
	}

	// No asset should exist for the NXDOMAIN candidate.
	for _, a := range page.Items {
		if a.Hostname != nil && *a.Hostname == "missing."+domainValue {
			t.Errorf("did not expect an asset for the NXDOMAIN candidate, got %+v", a)
		}
	}

	ipAsset := findByIP(t, page.Items, "192.0.2.20")
	if ipAsset.Type != domainasset.TypeIP {
		t.Errorf("asset.Type = %s, want %s", ipAsset.Type, domainasset.TypeIP)
	}

	evidence, err := assets.ListEvidence(context.Background(), assetrepo.EvidenceListFilter{AssetID: domainAsset.ID})
	if err != nil {
		t.Fatalf("ListEvidence() failed: %v", err)
	}
	if len(evidence.Items) == 0 {
		t.Fatal("expected at least one DNS_RECORD evidence entry for the domain asset")
	}
	if evidence.Items[0].EvidenceType != domainasset.EvidenceDNSRecord {
		t.Errorf("evidence type = %s, want %s", evidence.Items[0].EvidenceType, domainasset.EvidenceDNSRecord)
	}
}

func TestDNSPersistence_RescanPreservesFirstSeenAdvancesLastSeen(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	server, err := dnsfixture.New()
	if err != nil {
		t.Fatalf("starting DNS fixture: %v", err)
	}
	defer func() { _ = server.Close() }()

	domainValue := uniqueDNSDomain("rescan")
	if err := server.SetRecords(domainValue+".", dns.TypeA, domainValue+". 300 IN A 192.0.2.30"); err != nil {
		t.Fatalf("SetRecords: %v", err)
	}

	target := getOrCreateAuthorizedDNSTarget(t, targets, domainValue)
	req := discoverysvc.DNSRequest{
		TargetType: domaintarget.TypeDomain, TargetValue: domainValue,
		Config: dnsTestConfig(server),
	}
	req.Config.RecordTypes = []discoverydns.RecordType{discoverydns.TypeA}

	if _, _, err := discovery.RunDNS(context.Background(), req); err != nil {
		t.Fatalf("first RunDNS() failed: %v", err)
	}
	firstPage, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID, Type: domainasset.TypeDomain})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	first := findByHostname(t, firstPage.Items, domainValue)

	firstEvidence, err := assets.ListEvidence(context.Background(), assetrepo.EvidenceListFilter{AssetID: first.ID})
	if err != nil {
		t.Fatalf("ListEvidence() failed: %v", err)
	}
	if len(firstEvidence.Items) != 1 {
		t.Fatalf("expected exactly 1 evidence entry after the first scan, got %d", len(firstEvidence.Items))
	}

	time.Sleep(10 * time.Millisecond)

	if _, _, err := discovery.RunDNS(context.Background(), req); err != nil {
		t.Fatalf("second RunDNS() failed: %v", err)
	}
	secondPage, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID, Type: domainasset.TypeDomain})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	second := findByHostname(t, secondPage.Items, domainValue)

	if second.ID != first.ID {
		t.Fatalf("re-scanning created a new asset row: %v vs %v", first.ID, second.ID)
	}
	if !second.FirstSeen.Equal(first.FirstSeen) {
		t.Errorf("FirstSeen changed across re-scan: %v -> %v", first.FirstSeen, second.FirstSeen)
	}
	if !second.LastSeen.After(first.LastSeen) {
		t.Errorf("LastSeen did not advance across re-scan: %v -> %v", first.LastSeen, second.LastSeen)
	}

	secondEvidence, err := assets.ListEvidence(context.Background(), assetrepo.EvidenceListFilter{AssetID: second.ID})
	if err != nil {
		t.Fatalf("ListEvidence() failed: %v", err)
	}
	if len(secondEvidence.Items) != 1 {
		t.Errorf("re-scanning an unchanged record created a new evidence entry: got %d, want 1 (dedup by record identity, TTL excluded)", len(secondEvidence.Items))
	}

	// Now simulate a real DNS change and verify old evidence is preserved
	// alongside new evidence (phase5.md §37/§62/§75) — never overwritten
	// or erased.
	if err := server.SetRecords(domainValue+".", dns.TypeA, domainValue+". 300 IN A 192.0.2.99"); err != nil {
		t.Fatalf("SetRecords (changed): %v", err)
	}
	if _, _, err := discovery.RunDNS(context.Background(), req); err != nil {
		t.Fatalf("third RunDNS() (after record change) failed: %v", err)
	}
	thirdEvidence, err := assets.ListEvidence(context.Background(), assetrepo.EvidenceListFilter{AssetID: second.ID})
	if err != nil {
		t.Fatalf("ListEvidence() failed: %v", err)
	}
	if len(thirdEvidence.Items) != 2 {
		t.Fatalf("expected 2 evidence entries after a DNS record change (old preserved + new added), got %d", len(thirdEvidence.Items))
	}
	values := map[string]bool{}
	for _, e := range thirdEvidence.Items {
		if v, ok := e.EvidenceData["value"].(string); ok {
			values[v] = true
		}
	}
	if !values["192.0.2.30"] || !values["192.0.2.99"] {
		t.Errorf("expected evidence for both the old (192.0.2.30) and new (192.0.2.99) A values, got %+v", values)
	}
}

func TestDNSPersistence_WildcardExcludedFromDiscoveredCount(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	server, err := dnsfixture.New()
	if err != nil {
		t.Fatalf("starting DNS fixture: %v", err)
	}
	defer func() { _ = server.Close() }()

	domainValue := uniqueDNSDomain("wildcard")
	if err := server.SetRecords(domainValue+".", dns.TypeA, domainValue+". 300 IN A 192.0.2.1"); err != nil {
		t.Fatalf("SetRecords: %v", err)
	}
	if err := server.SetWildcard(domainValue+".", "*."+domainValue+". 300 IN A 203.0.113.50"); err != nil {
		t.Fatalf("SetWildcard: %v", err)
	}
	if err := server.SetRecords("api."+domainValue+".", dns.TypeA, "api."+domainValue+". 300 IN A 192.0.2.77"); err != nil {
		t.Fatalf("SetRecords api A (distinct override under wildcard): %v", err)
	}

	target := getOrCreateAuthorizedDNSTarget(t, targets, domainValue)

	summary, _, err := discovery.RunDNS(context.Background(), discoverysvc.DNSRequest{
		TargetType: domaintarget.TypeDomain, TargetValue: domainValue,
		EnumerateSubdomains: true,
		Config:              dnsConfigWithWords(server, []string{"api", "random1", "random2"}),
	})
	if err != nil {
		t.Fatalf("RunDNS() failed: %v", err)
	}
	if !summary.WildcardDetected {
		t.Fatal("expected WildcardDetected = true")
	}
	if summary.SubdomainsDiscovered != 1 {
		t.Errorf("SubdomainsDiscovered = %d, want 1 (only api, a distinct override — random1/random2 are wildcard noise)", summary.SubdomainsDiscovered)
	}

	page, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID, Type: domainasset.TypeSubdomain})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	for _, a := range page.Items {
		if a.Hostname != nil && (*a.Hostname == "random1."+domainValue || *a.Hostname == "random2."+domainValue) {
			t.Errorf("wildcard noise must not be persisted as a subdomain asset, got %+v", a)
		}
	}
	findByHostname(t, page.Items, "api."+domainValue)
}

// TestDNSPersistence_ScopeEnforcedEndToEnd is phase5.md §78's persistence-
// level scope check. Every wordlist-derived candidate is, by construction
// (GenerateCandidates always suffixes the target domain via JoinLabel),
// already a subdomain of the target — filterInScope's out-of-scope
// rejection path (e.g. "evil-example.test" for a target of "example.test")
// is exercised directly in scanner_test.go's
// TestFilterInScope_RejectsOutOfScopeAllowsInScope, since the candidate-
// generation pipeline itself cannot produce an out-of-scope name to feed
// through here. This test instead verifies the whole pipeline — including
// the scope check every candidate passes through — persists only the
// genuinely in-scope, resolved candidate end-to-end.
func TestDNSPersistence_ScopeEnforcedEndToEnd(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	server, err := dnsfixture.New()
	if err != nil {
		t.Fatalf("starting DNS fixture: %v", err)
	}
	defer func() { _ = server.Close() }()

	domainValue := uniqueDNSDomain("scope")
	if err := server.SetRecords(domainValue+".", dns.TypeA, domainValue+". 300 IN A 192.0.2.1"); err != nil {
		t.Fatalf("SetRecords: %v", err)
	}
	if err := server.SetRecords("api."+domainValue+".", dns.TypeA, "api."+domainValue+". 300 IN A 192.0.2.2"); err != nil {
		t.Fatalf("SetRecords api: %v", err)
	}

	target := getOrCreateAuthorizedDNSTarget(t, targets, domainValue)

	summary, _, err := discovery.RunDNS(context.Background(), discoverysvc.DNSRequest{
		TargetType: domaintarget.TypeDomain, TargetValue: domainValue,
		EnumerateSubdomains: true,
		Config:              dnsConfigWithWords(server, []string{"api"}),
	})
	if err != nil {
		t.Fatalf("RunDNS() failed: %v", err)
	}
	if summary.SubdomainsDiscovered != 1 {
		t.Errorf("SubdomainsDiscovered = %d, want 1", summary.SubdomainsDiscovered)
	}

	page, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID, Type: domainasset.TypeSubdomain})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	findByHostname(t, page.Items, "api."+domainValue)
}

func TestDNSPersistence_TXTSecretRedactedInEvidence(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	server, err := dnsfixture.New()
	if err != nil {
		t.Fatalf("starting DNS fixture: %v", err)
	}
	defer func() { _ = server.Close() }()

	domainValue := uniqueDNSDomain("secret")
	if err := server.SetRecords(domainValue+".", dns.TypeTXT, domainValue+`. 300 IN TXT "api_key=sk-live-shouldnotleak"`); err != nil {
		t.Fatalf("SetRecords TXT: %v", err)
	}

	target := getOrCreateAuthorizedDNSTarget(t, targets, domainValue)
	req := discoverysvc.DNSRequest{TargetType: domaintarget.TypeDomain, TargetValue: domainValue, Config: dnsTestConfig(server)}
	req.Config.RecordTypes = []discoverydns.RecordType{discoverydns.TypeTXT}

	if _, _, err := discovery.RunDNS(context.Background(), req); err != nil {
		t.Fatalf("RunDNS() failed: %v", err)
	}

	page, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID, Type: domainasset.TypeDomain})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	found := findByHostname(t, page.Items, domainValue)

	evidence, err := assets.ListEvidence(context.Background(), assetrepo.EvidenceListFilter{AssetID: found.ID})
	if err != nil {
		t.Fatalf("ListEvidence() failed: %v", err)
	}
	if len(evidence.Items) == 0 {
		t.Fatal("expected at least one evidence entry")
	}
	value, _ := evidence.Items[0].EvidenceData["value"].(string)
	if value == "api_key=sk-live-shouldnotleak" {
		t.Errorf("secret was persisted unredacted in evidence: %q", value)
	}
}

func TestDNSPersistence_UnauthorizedTargetRefused(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	server, err := dnsfixture.New()
	if err != nil {
		t.Fatalf("starting DNS fixture: %v", err)
	}
	defer func() { _ = server.Close() }()

	domainValue := uniqueDNSDomain("unauthorized")
	target, err := targets.Create(context.Background(), targetsvc.CreateInput{
		Name: "unauthorized DNS target", Type: domaintarget.TypeDomain, Value: domainValue,
	})
	if err != nil {
		t.Fatalf("creating target: %v", err)
	}

	_, _, err = discovery.RunDNS(context.Background(), discoverysvc.DNSRequest{
		TargetType: domaintarget.TypeDomain, TargetValue: domainValue, Config: dnsTestConfig(server),
	})
	if err == nil {
		t.Fatal("expected RunDNS() to refuse an unauthorized target")
	}

	page, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("expected no assets persisted for a refused (unauthorized) scan, got %d", len(page.Items))
	}
}

func TestDNSPersistence_DryRunPersistsNothing(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	server, err := dnsfixture.New()
	if err != nil {
		t.Fatalf("starting DNS fixture: %v", err)
	}
	defer func() { _ = server.Close() }()

	domainValue := uniqueDNSDomain("dryrun")
	if err := server.SetRecords(domainValue+".", dns.TypeA, domainValue+". 300 IN A 192.0.2.5"); err != nil {
		t.Fatalf("SetRecords: %v", err)
	}
	target := getOrCreateAuthorizedDNSTarget(t, targets, domainValue)

	summary, dryRun, err := discovery.RunDNS(context.Background(), discoverysvc.DNSRequest{
		TargetType: domaintarget.TypeDomain, TargetValue: domainValue,
		EnumerateSubdomains: true, DryRun: true,
		Config: dnsConfigWithWords(server, []string{"api"}),
	})
	if err != nil {
		t.Fatalf("RunDNS() failed: %v", err)
	}
	if summary != nil {
		t.Fatal("expected a dry-run report, not a Summary")
	}
	if dryRun == nil || len(dryRun.SubdomainCandidates) != 1 {
		t.Fatalf("expected a dry-run report naming 1 subdomain candidate, got %+v", dryRun)
	}

	page, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("expected no assets persisted in dry-run mode, got %d", len(page.Items))
	}
}

func TestDNSPersistence_LargeWordlistRespectsMaxCandidates(t *testing.T) {
	// A large wordlist at depth 2 (comprehensive-profile scale) must never
	// exceed max_candidates, end-to-end from GenerateCandidates through
	// to what a real scan would enumerate (phase5.md §23/§64).
	words := make([]string, 60)
	for i := range words {
		words[i] = uniqueValue("w")
	}

	candidates, err := discoverydns.GenerateCandidates("example.test", words, 2, 500)
	if err != nil {
		t.Fatalf("GenerateCandidates: %v", err)
	}
	if len(candidates) != 500 {
		t.Fatalf("GenerateCandidates with maxCandidates=500 returned %d candidates, want exactly 500 (cap must never be exceeded, phase5.md §23/§64)", len(candidates))
	}
}

func getOrCreateAuthorizedDNSTarget(t *testing.T, targets *targetsvc.Service, domainValue string) domaintarget.Target {
	t.Helper()
	ctx := context.Background()

	existing, err := targets.GetByValue(ctx, domaintarget.TypeDomain, domainValue)
	if err == nil {
		if existing.IsAuthorized() {
			return existing
		}
		authorized, err := targets.UpdateAuthorizationStatus(ctx, existing.ID, domaintarget.AuthorizationAuthorized)
		if err != nil {
			t.Fatalf("authorizing existing target: %v", err)
		}
		return authorized
	}

	created, err := targets.Create(ctx, targetsvc.CreateInput{
		Name: "DNS discovery test target", Type: domaintarget.TypeDomain, Value: domainValue,
	})
	if err != nil {
		t.Fatalf("creating target: %v", err)
	}
	authorized, err := targets.UpdateAuthorizationStatus(ctx, created.ID, domaintarget.AuthorizationAuthorized)
	if err != nil {
		t.Fatalf("authorizing target: %v", err)
	}
	return authorized
}

func dnsConfigWithWords(server *dnsfixture.Server, words []string) discoverydns.Config {
	cfg := dnsTestConfig(server)
	cfg.RecordTypes = []discoverydns.RecordType{discoverydns.TypeA}
	cfg.Subdomains.Words = words
	return cfg
}

// uniqueDNSDomain returns a unique, valid domain value using the same
// "<prefix>-<uuid>.integration.test" shape uniqueValue already provides
// for every other integration test's target values.
func uniqueDNSDomain(prefix string) string {
	return uniqueValue(prefix)
}

func findByHostname(t *testing.T, items []domainasset.Asset, hostname string) domainasset.Asset {
	t.Helper()
	for _, a := range items {
		if a.Hostname != nil && *a.Hostname == hostname {
			return a
		}
	}
	t.Fatalf("no asset found for hostname %q among %d assets", hostname, len(items))
	return domainasset.Asset{}
}

// findByIP matches by prefix — Asset.IP is stored/rendered as a CIDR
// (postgres inet), e.g. "192.0.2.20/32", not a bare address.
func findByIP(t *testing.T, items []domainasset.Asset, ip string) domainasset.Asset {
	t.Helper()
	for _, a := range items {
		if a.IP != nil && strings.HasPrefix(*a.IP, ip) {
			return a
		}
	}
	t.Fatalf("no asset found for IP %q among %d assets", ip, len(items))
	return domainasset.Asset{}
}
