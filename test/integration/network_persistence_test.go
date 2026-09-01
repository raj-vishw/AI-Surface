//go:build integration

package integration

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	discoverynet "ai-recon-platform/internal/discovery/network"
	discoverysvc "ai-recon-platform/internal/discovery/service"
	domainasset "ai-recon-platform/internal/domain/asset"
	domaintarget "ai-recon-platform/internal/domain/target"
	assetrepo "ai-recon-platform/internal/repository/asset"
	assetsvc "ai-recon-platform/internal/service/asset"
	targetsvc "ai-recon-platform/internal/service/target"
	httpfixture "ai-recon-platform/test/fixtures/http"
	tcpfixture "ai-recon-platform/test/fixtures/tcp"
)

// networkTestConfig returns a small, fast network discovery configuration
// suitable for integration tests against local fixtures.
func networkTestConfig() discoverynet.Config {
	return discoverynet.Config{
		ConnectTimeout: 2 * time.Second,
		MaxConcurrency: 10,
		MaxHosts:       256,
	}
}

// getOrCreateAuthorizedTarget returns an authorized target for (typ,
// value), creating it if it doesn't already exist. Network discovery
// targets a fixed value (an IP address, unlike Phase 3's HTTP fixture
// targets which embed a random ephemeral port in a URL and are therefore
// always unique) — reusing an existing row across test runs against a
// shared dev database is the correct, idempotent behavior here, the same
// way a real operator creates one target for "127.0.0.1" once and reuses
// it for every future scan.
func getOrCreateAuthorizedTarget(t *testing.T, targets *targetsvc.Service, typ domaintarget.Type, value string) domaintarget.Target {
	t.Helper()
	ctx := context.Background()

	existing, err := targets.GetByValue(ctx, typ, value)
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
		Name: "network discovery test target", Type: typ, Value: value,
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

func TestNetworkPersistence_EndToEnd(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	tcpSrv, err := tcpfixture.New()
	if err != nil {
		t.Fatalf("starting tcp fixture: %v", err)
	}
	defer func() { _ = tcpSrv.Close() }()
	closedPort, err := tcpfixture.ClosedPort()
	if err != nil {
		t.Fatalf("reserving closed port: %v", err)
	}

	target := getOrCreateAuthorizedTarget(t, targets, domaintarget.TypeIP, "127.0.0.1")

	cfg := networkTestConfig()
	cfg.AICandidatePorts = []int{tcpSrv.Port()}
	summary, dryRun, err := discovery.RunNetwork(context.Background(), discoverysvc.NetworkRequest{
		TargetType: domaintarget.TypeIP, TargetValue: "127.0.0.1",
		PortsSpec: portsCSV(tcpSrv.Port(), closedPort), Config: cfg,
	})
	if err != nil {
		t.Fatalf("RunNetwork() failed: %v", err)
	}
	if dryRun != nil {
		t.Fatal("expected a real scan, not a dry-run report")
	}
	if summary.Open != 1 {
		t.Errorf("Open = %d, want 1", summary.Open)
	}
	if summary.Closed != 1 {
		t.Errorf("Closed = %d, want 1", summary.Closed)
	}
	if summary.AICandidates != 1 {
		t.Errorf("AICandidates = %d, want 1 (configured AI candidate port was open)", summary.AICandidates)
	}

	page, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	var found *domainasset.Asset
	for i, a := range page.Items {
		if a.Port != nil && *a.Port == tcpSrv.Port() {
			found = &page.Items[i]
		}
	}
	if found == nil {
		t.Fatalf("expected an asset for the open port %d, got assets: %+v", tcpSrv.Port(), page.Items)
	}
	if found.Type != domainasset.TypePort {
		t.Errorf("asset.Type = %s, want %s", found.Type, domainasset.TypePort)
	}
	if found.Source != "network" {
		t.Errorf("asset.Source = %q, want %q", found.Source, "network")
	}
	if found.Protocol == nil || *found.Protocol != "tcp" {
		t.Errorf("asset.Protocol = %v, want \"tcp\"", found.Protocol)
	}

	// No asset should exist for the closed port.
	for _, a := range page.Items {
		if a.Port != nil && *a.Port == closedPort {
			t.Errorf("did not expect an asset for the closed port %d, got %+v", closedPort, a)
		}
	}

	evidence, err := assets.ListEvidence(context.Background(), assetrepo.EvidenceListFilter{AssetID: found.ID})
	if err != nil {
		t.Fatalf("ListEvidence() failed: %v", err)
	}
	if len(evidence.Items) == 0 {
		t.Fatal("expected at least one evidence record for the open port")
	}
	if evidence.Items[0].EvidenceType != domainasset.EvidencePortObservation {
		t.Errorf("evidence type = %s, want %s", evidence.Items[0].EvidenceType, domainasset.EvidencePortObservation)
	}
}

func TestNetworkPersistence_RescanPreservesFirstSeenAdvancesLastSeen(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	tcpSrv, err := tcpfixture.New()
	if err != nil {
		t.Fatalf("starting tcp fixture: %v", err)
	}
	defer func() { _ = tcpSrv.Close() }()

	target := getOrCreateAuthorizedTarget(t, targets, domaintarget.TypeIP, "127.0.0.1")
	req := discoverysvc.NetworkRequest{
		TargetType: domaintarget.TypeIP, TargetValue: "127.0.0.1",
		PortsSpec: portsCSV(tcpSrv.Port()), Config: networkTestConfig(),
	}

	if _, _, err := discovery.RunNetwork(context.Background(), req); err != nil {
		t.Fatalf("first RunNetwork() failed: %v", err)
	}
	firstPage, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID, Type: domainasset.TypePort})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	first := findByPort(t, firstPage.Items, tcpSrv.Port())

	time.Sleep(10 * time.Millisecond)

	if _, _, err := discovery.RunNetwork(context.Background(), req); err != nil {
		t.Fatalf("second RunNetwork() failed: %v", err)
	}
	secondPage, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID, Type: domainasset.TypePort})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	second := findByPort(t, secondPage.Items, tcpSrv.Port())

	if second.ID != first.ID {
		t.Fatalf("re-scanning created a new asset row: %v vs %v", first.ID, second.ID)
	}
	if !second.FirstSeen.Equal(first.FirstSeen) {
		t.Errorf("FirstSeen changed across re-scan: %v -> %v", first.FirstSeen, second.FirstSeen)
	}
	if !second.LastSeen.After(first.LastSeen) {
		t.Errorf("LastSeen did not advance across re-scan: %v -> %v", first.LastSeen, second.LastSeen)
	}

	// No duplicate logical assets for this port.
	count := 0
	for _, a := range secondPage.Items {
		if a.Port != nil && *a.Port == tcpSrv.Port() {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 asset for port %d after re-scan, got %d", tcpSrv.Port(), count)
	}
}

func TestNetworkPersistence_UnauthorizedTargetRefused(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	closedPort, err := tcpfixture.ClosedPort()
	if err != nil {
		t.Fatalf("reserving port: %v", err)
	}

	// A freshly-created, deliberately-unique HOST target that is never
	// authorized.
	hostValue := uniqueValue("unauthorized-network")
	target, err := targets.Create(context.Background(), targetsvc.CreateInput{
		Name: "unauthorized network target", Type: domaintarget.TypeHost, Value: hostValue,
	})
	if err != nil {
		t.Fatalf("creating target: %v", err)
	}

	_, _, err = discovery.RunNetwork(context.Background(), discoverysvc.NetworkRequest{
		TargetType: domaintarget.TypeHost, TargetValue: hostValue,
		PortsSpec: portsCSV(closedPort), Config: networkTestConfig(),
	})
	if err == nil {
		t.Fatal("expected RunNetwork() to refuse an unauthorized target")
	}

	page, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("expected no assets persisted for a refused (unauthorized) scan, got %d", len(page.Items))
	}
}

func TestNetworkPersistence_DryRunPersistsNothing(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	tcpSrv, err := tcpfixture.New()
	if err != nil {
		t.Fatalf("starting tcp fixture: %v", err)
	}
	defer func() { _ = tcpSrv.Close() }()

	hostValue := uniqueValue("dryrun-network")
	target, err := targets.Create(context.Background(), targetsvc.CreateInput{
		Name: "dry run network target", Type: domaintarget.TypeHost, Value: hostValue,
	})
	if err != nil {
		t.Fatalf("creating target: %v", err)
	}
	if _, err := targets.UpdateAuthorizationStatus(context.Background(), target.ID, domaintarget.AuthorizationAuthorized); err != nil {
		t.Fatalf("authorizing target: %v", err)
	}

	summary, dryRun, err := discovery.RunNetwork(context.Background(), discoverysvc.NetworkRequest{
		TargetType: domaintarget.TypeHost, TargetValue: hostValue,
		PortsSpec: portsCSV(tcpSrv.Port()), DryRun: true, Config: networkTestConfig(),
	})
	if err != nil {
		t.Fatalf("RunNetwork() failed: %v", err)
	}
	if summary != nil {
		t.Fatal("expected a dry-run report, not a Summary")
	}
	if dryRun == nil || len(dryRun.Hosts) != 1 || len(dryRun.Ports) != 1 {
		t.Fatalf("expected a dry-run report naming 1 host and 1 port, got %+v", dryRun)
	}

	page, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: target.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("expected no assets persisted in dry-run mode, got %d", len(page.Items))
	}
}

// TestMultiSourceDiscovery_ConsistentNotContradictory is phase4.md §43's
// required test: running Phase 3 HTTP discovery and Phase 4 network
// discovery against the same host:port must not create contradictory
// duplicate assets. They legitimately produce two different Asset rows
// (PORT vs HTTP_ENDPOINT — different layers of the same stack, exactly
// what Phase 2's asset model's distinct types exist for), not a single
// merged one — this test asserts that difference is consistent
// (both describe a reachable/serving port) rather than contradictory
// (e.g. one claiming closed while the other served a response), and that
// re-running either source doesn't multiply rows within its own type.
func TestMultiSourceDiscovery_ConsistentNotContradictory(t *testing.T) {
	pool := setupDB(t)
	targets := targetsvc.NewService(pool)
	assets := assetsvc.NewService(pool)
	discovery := discoverysvc.NewService(targets, assets, nil)

	fixture := httpfixture.New()
	defer fixture.Close()

	urlTarget := createAuthorizedFixtureTarget(t, targets, fixture)
	ipTarget := getOrCreateAuthorizedTarget(t, targets, domaintarget.TypeIP, "127.0.0.1")

	httpSummary, _, err := discovery.Run(context.Background(), discoverysvc.Request{
		TargetType: domaintarget.TypeURL, TargetValue: fixture.URL(),
		Config: discoveryTestConfig([]string{"/"}),
	})
	if err != nil {
		t.Fatalf("HTTP Run() failed: %v", err)
	}
	if httpSummary.Successful != 1 {
		t.Fatalf("expected the HTTP scan to succeed, got %+v", httpSummary)
	}

	fixturePort := fixturePortFromURL(t, fixture.URL())
	networkSummary, _, err := discovery.RunNetwork(context.Background(), discoverysvc.NetworkRequest{
		TargetType: domaintarget.TypeIP, TargetValue: "127.0.0.1",
		PortsSpec: portsCSV(fixturePort), Config: networkTestConfig(),
	})
	if err != nil {
		t.Fatalf("RunNetwork() failed: %v", err)
	}
	if networkSummary.Open != 1 {
		t.Fatalf("expected the network scan to find the port open, got %+v", networkSummary)
	}

	httpAssets, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: urlTarget.ID})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(httpAssets.Items) != 1 {
		t.Fatalf("expected exactly 1 HTTP-discovered asset, got %d", len(httpAssets.Items))
	}
	httpAsset := httpAssets.Items[0]
	if httpAsset.Type == domainasset.TypePort {
		t.Errorf("HTTP-discovered asset should not be typed PORT, got %s", httpAsset.Type)
	}

	networkAssets, err := assets.List(context.Background(), assetrepo.ListFilter{TargetID: ipTarget.ID, Type: domainasset.TypePort})
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	var networkAsset *domainasset.Asset
	for i, a := range networkAssets.Items {
		if a.Port != nil && *a.Port == fixturePort {
			networkAsset = &networkAssets.Items[i]
		}
	}
	if networkAsset == nil {
		t.Fatalf("expected a network-discovered PORT asset for port %d, got %+v", fixturePort, networkAssets.Items)
	}

	// Consistency check: both sources agree the port/endpoint is
	// reachable and serving — neither claims it's closed/unreachable
	// while the other reports success.
	if networkAsset.Status == domainasset.StatusRetired {
		t.Error("network-discovered asset should not be RETIRED — the port was open")
	}
	if httpAsset.Port == nil || networkAsset.Port == nil || *httpAsset.Port != *networkAsset.Port {
		t.Errorf("HTTP and network assets disagree on port: %v vs %v", httpAsset.Port, networkAsset.Port)
	}
	if httpAsset.Hostname == nil || networkAsset.Hostname == nil || *httpAsset.Hostname != *networkAsset.Hostname {
		t.Errorf("HTTP and network assets disagree on hostname: %v vs %v", httpAsset.Hostname, networkAsset.Hostname)
	}
}

func portsCSV(ports ...int) string {
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = strconv.Itoa(p)
	}
	return strings.Join(strs, ",")
}

func findByPort(t *testing.T, assets []domainasset.Asset, port int) domainasset.Asset {
	t.Helper()
	for _, a := range assets {
		if a.Port != nil && *a.Port == port {
			return a
		}
	}
	t.Fatalf("no asset found for port %d among %d assets", port, len(assets))
	return domainasset.Asset{}
}

func fixturePortFromURL(t *testing.T, rawURL string) int {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parsing fixture URL %q: %v", rawURL, err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("fixture URL %q has no numeric port: %v", rawURL, err)
	}
	return port
}
