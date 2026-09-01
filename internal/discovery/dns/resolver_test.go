package dns

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"

	dnsfixture "ai-recon-platform/test/fixtures/dns"
)

// startFixture starts the local DNS test fixture (test/fixtures/dns) on an
// ephemeral port and an ExplicitResolver pointed at it — no public DNS
// dependency (phase5.md §57).
func startFixture(t *testing.T) (*dnsfixture.Server, Resolver) {
	t.Helper()
	server, err := dnsfixture.New()
	if err != nil {
		t.Fatalf("starting DNS fixture: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	resolver, err := NewExplicitResolver([]string{server.Addr()}, 2*time.Second)
	if err != nil {
		t.Fatalf("NewExplicitResolver: %v", err)
	}
	return server, resolver
}

func TestResolver_A(t *testing.T) {
	_, resolver := startFixture(t)
	result, err := resolver.Lookup(context.Background(), "example.test", TypeA)
	if err != nil {
		t.Fatalf("Lookup A: %v", err)
	}
	if len(result.Records) == 0 || result.Records[0].Value == "" {
		t.Fatalf("Lookup A: no records returned")
	}
	if result.Records[0].Type != TypeA {
		t.Errorf("record Type = %s, want A", result.Records[0].Type)
	}
}

func TestResolver_AAAA(t *testing.T) {
	_, resolver := startFixture(t)
	result, err := resolver.Lookup(context.Background(), "example.test", TypeAAAA)
	if err != nil {
		t.Fatalf("Lookup AAAA: %v", err)
	}
	if len(result.Records) == 0 {
		t.Fatalf("Lookup AAAA: no records returned")
	}
}

func TestResolver_CNAME(t *testing.T) {
	_, resolver := startFixture(t)
	result, err := resolver.Lookup(context.Background(), "service.example.test", TypeCNAME)
	if err != nil {
		t.Fatalf("Lookup CNAME: %v", err)
	}
	if len(result.Records) == 0 || result.Records[0].Value != "backend.example.test" {
		t.Fatalf("Lookup CNAME = %+v, want target backend.example.test", result.Records)
	}
}

func TestResolver_MX(t *testing.T) {
	_, resolver := startFixture(t)
	result, err := resolver.Lookup(context.Background(), "example.test", TypeMX)
	if err != nil {
		t.Fatalf("Lookup MX: %v", err)
	}
	if len(result.Records) == 0 || result.Records[0].Priority == nil {
		t.Fatalf("Lookup MX = %+v, want a record with a Priority set", result.Records)
	}
}

func TestResolver_NS(t *testing.T) {
	_, resolver := startFixture(t)
	result, err := resolver.Lookup(context.Background(), "example.test", TypeNS)
	if err != nil {
		t.Fatalf("Lookup NS: %v", err)
	}
	if len(result.Records) < 2 {
		t.Fatalf("Lookup NS = %+v, want at least 2 NS records (ns1, ns2)", result.Records)
	}
}

func TestResolver_TXT(t *testing.T) {
	_, resolver := startFixture(t)
	result, err := resolver.Lookup(context.Background(), "example.test", TypeTXT)
	if err != nil {
		t.Fatalf("Lookup TXT: %v", err)
	}
	if len(result.Records) == 0 {
		t.Fatalf("Lookup TXT: no records returned")
	}
}

func TestResolver_SOA(t *testing.T) {
	_, resolver := startFixture(t)
	result, err := resolver.Lookup(context.Background(), "example.test", TypeSOA)
	if err != nil {
		t.Fatalf("Lookup SOA: %v", err)
	}
	if len(result.Records) == 0 || result.Records[0].SOA == nil {
		t.Fatalf("Lookup SOA = %+v, want a record with SOA structured data", result.Records)
	}
	if result.Records[0].SOA.Serial == 0 {
		t.Errorf("SOA.Serial = 0, want a nonzero serial")
	}
}

func TestResolver_CAA(t *testing.T) {
	_, resolver := startFixture(t)
	result, err := resolver.Lookup(context.Background(), "example.test", TypeCAA)
	if err != nil {
		t.Fatalf("Lookup CAA: %v", err)
	}
	if len(result.Records) == 0 || result.Records[0].CAA == nil {
		t.Fatalf("Lookup CAA = %+v, want a record with CAA structured data", result.Records)
	}
	if result.Records[0].CAA.Tag == "" {
		t.Errorf("CAA.Tag is empty, want e.g. \"issue\"")
	}
}

func TestResolver_PTR(t *testing.T) {
	server, resolver := startFixture(t)
	// api.example.test has an A record in the default zone; find its
	// address via a forward lookup first so this test doesn't hardcode the
	// fixture's internal IP assignment.
	fwd, err := resolver.Lookup(context.Background(), "api.example.test", TypeA)
	if err != nil || len(fwd.Records) == 0 {
		t.Fatalf("precondition: forward A lookup for api.example.test failed: %v", err)
	}
	ip := fwd.Records[0].Value

	result, err := resolver.LookupPTR(context.Background(), ip)
	if err != nil {
		t.Fatalf("LookupPTR(%s): %v", ip, err)
	}
	if len(result.Records) == 0 {
		t.Fatalf("LookupPTR(%s): no records returned (fixture must have a matching PTR entry)", ip)
	}
	_ = server // fixture kept alive via startFixture's t.Cleanup
}

func TestResolver_NXDOMAIN(t *testing.T) {
	_, resolver := startFixture(t)
	result, err := resolver.Lookup(context.Background(), "missing.example.test", TypeA)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if classify(result) != StateNXDOMAIN {
		t.Errorf("classify(missing.example.test) = %s, want NXDOMAIN", classify(result))
	}
}

func TestResolver_NODATA(t *testing.T) {
	_, resolver := startFixture(t)
	// example.test exists (has A/AAAA/MX/... records) but no CAA-adjacent
	// TXT-only-shaped query type it lacks: query a type that returns no
	// answer for a name known to exist. dev.example.test has only an A
	// record — MX should NODATA, not NXDOMAIN.
	result, err := resolver.Lookup(context.Background(), "dev.example.test", TypeMX)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if classify(result) != StateNoAnswer {
		t.Errorf("classify(dev.example.test MX) = %s, want NO_ANSWER (NODATA) — name exists, just not with this type", classify(result))
	}
}

func TestResolver_Timeout(t *testing.T) {
	// A resolver pointed at a closed port with a very short timeout must
	// classify as a timeout, not hang or return a misleading NXDOMAIN.
	resolver, err := NewExplicitResolver([]string{"127.0.0.1:1"}, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("NewExplicitResolver: %v", err)
	}
	_, err = resolver.Lookup(context.Background(), "example.test", TypeA)
	if err == nil {
		t.Fatalf("Lookup against an unreachable resolver returned no error")
	}
	if classifyTransportError(err) == StateNXDOMAIN || classifyTransportError(err) == StateResolved {
		t.Errorf("classifyTransportError(%v) = %s, want TIMEOUT or ERROR, never a resolution state", err, classifyTransportError(err))
	}
}

func TestResolver_ContextCancellation(t *testing.T) {
	_, resolver := startFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := resolver.Lookup(ctx, "example.test", TypeA)
	if err == nil {
		t.Fatalf("Lookup with a cancelled context returned no error")
	}
}

func TestResolver_TXTSecretRedacted(t *testing.T) {
	server, resolver := startFixture(t)
	if err := server.SetRecords("secret.example.test.", dns.TypeTXT, `secret.example.test. 300 IN TXT "api_key=sk-live-shouldnotleak"`); err != nil {
		t.Fatalf("SetRecords: %v", err)
	}
	result, err := resolver.Lookup(context.Background(), "secret.example.test", TypeTXT)
	if err != nil {
		t.Fatalf("Lookup TXT: %v", err)
	}
	if len(result.Records) == 0 {
		t.Fatalf("Lookup TXT: no records returned")
	}
	if result.Records[0].Value == "api_key=sk-live-shouldnotleak" {
		t.Errorf("TXT secret was not redacted by the resolver: %q", result.Records[0].Value)
	}
}

func TestResolver_InvalidResolverAddress(t *testing.T) {
	if _, err := NewExplicitResolver([]string{"not-a-valid-address"}, time.Second); err == nil {
		t.Errorf("NewExplicitResolver(invalid address) = nil error, want error")
	}
}

func TestResolver_NoServers(t *testing.T) {
	if _, err := NewExplicitResolver(nil, time.Second); err == nil {
		t.Errorf("NewExplicitResolver(no servers) = nil error, want error")
	}
}
