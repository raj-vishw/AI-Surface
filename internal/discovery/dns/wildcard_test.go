package dns

import (
	"context"
	"strings"
	"testing"
)

// mockResolver is a hand-rolled Resolver for unit tests that don't need a
// real DNS transport — resolves names present in records, NXDOMAINs
// everything else. Any name beginning with "wc-" (a wildcard probe label)
// matches wildcardValue when wildcardDomain is set and the name is under
// it, unless explicitly overridden in records first.
type mockResolver struct {
	records        map[string][]Record // key: normalized name + "|" + RecordType
	wildcardDomain string
	wildcardValue  string
}

func (m *mockResolver) Lookup(_ context.Context, name string, recordType RecordType) (LookupResult, error) {
	key := name + "|" + string(recordType)
	if recs, ok := m.records[key]; ok {
		return LookupResult{Rcode: 0, Records: recs}, nil
	}
	if m.wildcardDomain != "" && recordType == TypeA && strings.HasSuffix(name, "."+m.wildcardDomain) {
		return LookupResult{Rcode: 0, Records: []Record{{Name: name, Type: TypeA, Value: m.wildcardValue}}}, nil
	}
	return LookupResult{Rcode: 3 /* NXDOMAIN */}, nil // dns.RcodeNameError
}

func (m *mockResolver) LookupPTR(_ context.Context, ip string) (LookupResult, error) {
	if recs, ok := m.records[ip+"|PTR"]; ok {
		return LookupResult{Rcode: 0, Records: recs}, nil
	}
	return LookupResult{Rcode: 3}, nil
}

func TestDetectWildcard_Detected(t *testing.T) {
	resolver := &mockResolver{wildcardDomain: "wildcard.example.test", wildcardValue: "203.0.113.50"}

	detection, err := DetectWildcard(context.Background(), resolver, "wildcard.example.test", []RecordType{TypeA})
	if err != nil {
		t.Fatalf("DetectWildcard: %v", err)
	}
	if !detection.Detected {
		t.Fatalf("Detected = false, want true")
	}
	if len(detection.RecordSet) != 1 || detection.RecordSet[0] != "203.0.113.50" {
		t.Errorf("RecordSet = %v, want [203.0.113.50]", detection.RecordSet)
	}
}

func TestDetectWildcard_NotDetected_NoWildcardConfigured(t *testing.T) {
	resolver := &mockResolver{records: map[string][]Record{}}

	detection, err := DetectWildcard(context.Background(), resolver, "example.test", []RecordType{TypeA})
	if err != nil {
		t.Fatalf("DetectWildcard: %v", err)
	}
	if detection.Detected {
		t.Errorf("Detected = true, want false — no probe resolved anything")
	}
}

func TestDetectWildcard_NoAssetCreatedForProbes(t *testing.T) {
	// DetectWildcard's return type carries no Record/asset-shaped value for
	// the probe names themselves — only a baseline record set. This test
	// documents and locks that contract: RecordSet holds values, never names.
	resolver := &mockResolver{wildcardDomain: "wildcard.example.test", wildcardValue: "203.0.113.50"}
	detection, err := DetectWildcard(context.Background(), resolver, "wildcard.example.test", []RecordType{TypeA})
	if err != nil {
		t.Fatalf("DetectWildcard: %v", err)
	}
	for _, v := range detection.RecordSet {
		if strings.HasPrefix(v, "wc-") {
			t.Errorf("RecordSet leaked a probe label (%q) instead of a resolved value", v)
		}
	}
}

func TestWildcardDetection_MatchesWildcard(t *testing.T) {
	detection := WildcardDetection{Detected: true, RecordSet: []string{"203.0.113.50"}}

	if !detection.MatchesWildcard([]string{"203.0.113.50"}) {
		t.Errorf("MatchesWildcard(baseline value) = false, want true")
	}
	if detection.MatchesWildcard([]string{"192.0.2.77"}) {
		t.Errorf("MatchesWildcard(distinct value) = true, want false — a distinct record under a wildcard domain must still be recognized as genuine (phase5.md §58)")
	}
}

func TestWildcardDetection_MatchesWildcard_NotDetected(t *testing.T) {
	detection := WildcardDetection{Detected: false}
	if detection.MatchesWildcard([]string{"203.0.113.50"}) {
		t.Errorf("MatchesWildcard() = true when Detected is false, want false")
	}
}

func TestRandomLabel_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		label, err := randomLabel()
		if err != nil {
			t.Fatalf("randomLabel: %v", err)
		}
		if !strings.HasPrefix(label, "wc-") {
			t.Errorf("randomLabel() = %q, want wc- prefix", label)
		}
		if seen[label] {
			t.Fatalf("randomLabel() produced a duplicate: %q", label)
		}
		seen[label] = true
	}
}
