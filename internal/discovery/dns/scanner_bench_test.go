package dns

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	discoveryhttp "ai-recon-platform/internal/discovery/http"
	dnsfixture "ai-recon-platform/test/fixtures/dns"
)

// BenchmarkScanner_Scan measures one full DNS discovery run (record
// resolution + subdomain enumeration + wildcard detection + PTR) against
// the local fixture — no public DNS dependency (phase5.md §57/§68).
func BenchmarkScanner_Scan(b *testing.B) {
	server, err := dnsfixture.New()
	if err != nil {
		b.Fatalf("starting DNS fixture: %v", err)
	}
	defer func() { _ = server.Close() }()

	resolver, err := NewExplicitResolver([]string{server.Addr()}, 2*time.Second)
	if err != nil {
		b.Fatalf("NewExplicitResolver: %v", err)
	}

	cfg := Config{
		Timeout:        2 * time.Second,
		MaxConcurrency: 20,
		RecordTypes:    []RecordType{TypeA, TypeAAAA, TypeCNAME, TypeMX, TypeNS, TypeTXT, TypeSOA, TypeCAA},
		ReversePTR:     true,
		Subdomains:     SubdomainConfig{MaxCandidates: 100, MaxDepth: 1, WildcardDetection: true},
	}
	scanner := NewScanner(resolver, nil, cfg)

	scope, err := discoveryhttp.NewScopeValidator("https://example.test")
	if err != nil {
		b.Fatalf("NewScopeValidator: %v", err)
	}

	words := []string{"api", "www", "dev", "staging", "admin"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scanner.Scan(context.Background(), ScanRequest{
			TargetID:       uuid.New(),
			Domain:         "example.test",
			RecordTypes:    cfg.RecordTypes,
			SubdomainWords: words,
		}, scope)
		if err != nil {
			b.Fatalf("Scan: %v", err)
		}
	}
}

// BenchmarkGenerateCandidates measures candidate-generation throughput in
// isolation, at the comprehensive profile's scale (50 words, depth 2).
func BenchmarkGenerateCandidates(b *testing.B) {
	words := make([]string, 50)
	for i := range words {
		words[i] = uuid.New().String()[:8]
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := GenerateCandidates("example.test", words, 2, 10000); err != nil {
			b.Fatalf("GenerateCandidates: %v", err)
		}
	}
}
