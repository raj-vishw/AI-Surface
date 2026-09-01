package dns

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCandidates_Depth1(t *testing.T) {
	candidates, err := GenerateCandidates("example.test", []string{"api", "www"}, 1, 100)
	if err != nil {
		t.Fatalf("GenerateCandidates: %v", err)
	}
	want := []string{"api.example.test", "www.example.test"}
	assertNames(t, candidates, want)
}

func TestGenerateCandidates_DedupesCaseAndTrailingDot(t *testing.T) {
	candidates, err := GenerateCandidates("example.test", []string{"API", "api.", "api"}, 1, 100)
	if err != nil {
		t.Fatalf("GenerateCandidates: %v", err)
	}
	assertNames(t, candidates, []string{"api.example.test"})
}

func TestGenerateCandidates_Depth2Combinatorics(t *testing.T) {
	// depth 1: a, b (2 names); depth 2: combine [a,b] onto themselves -> a.a, b.a, a.b, b.b (4 names) = 6 total
	candidates, err := GenerateCandidates("example.test", []string{"a", "b"}, 2, 100)
	if err != nil {
		t.Fatalf("GenerateCandidates: %v", err)
	}
	if len(candidates) != 6 {
		names := make([]string, len(candidates))
		for i, c := range candidates {
			names[i] = c.Name
		}
		t.Fatalf("GenerateCandidates depth=2 len = %d, want 6; got %v", len(candidates), names)
	}
}

func TestGenerateCandidates_MaxCandidatesCap(t *testing.T) {
	candidates, err := GenerateCandidates("example.test", []string{"a", "b", "c"}, 2, 3)
	if err != nil {
		t.Fatalf("GenerateCandidates: %v", err)
	}
	if len(candidates) != 3 {
		t.Fatalf("GenerateCandidates with maxCandidates=3 returned %d candidates, want exactly 3", len(candidates))
	}
}

func TestGenerateCandidates_Deterministic(t *testing.T) {
	words := []string{"api", "dev", "staging", "www", "admin"}
	first, err := GenerateCandidates("example.test", words, 2, 8)
	if err != nil {
		t.Fatalf("GenerateCandidates: %v", err)
	}
	second, err := GenerateCandidates("example.test", words, 2, 8)
	if err != nil {
		t.Fatalf("GenerateCandidates: %v", err)
	}
	if len(first) != len(second) {
		t.Fatalf("non-deterministic candidate count: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].Name != second[i].Name {
			t.Fatalf("non-deterministic candidate order at index %d: %q vs %q", i, first[i].Name, second[i].Name)
		}
	}
}

func TestGenerateCandidates_SortedOutput(t *testing.T) {
	candidates, err := GenerateCandidates("example.test", []string{"www", "api", "dev"}, 1, 100)
	if err != nil {
		t.Fatalf("GenerateCandidates: %v", err)
	}
	for i := 1; i < len(candidates); i++ {
		if candidates[i-1].Name > candidates[i].Name {
			t.Fatalf("candidates not sorted: %q > %q", candidates[i-1].Name, candidates[i].Name)
		}
	}
}

func TestGenerateCandidates_EmptyWordsReturnsNil(t *testing.T) {
	candidates, err := GenerateCandidates("example.test", nil, 1, 100)
	if err != nil {
		t.Fatalf("GenerateCandidates: %v", err)
	}
	if len(candidates) != 0 {
		t.Errorf("GenerateCandidates(no words) = %d candidates, want 0", len(candidates))
	}
}

func TestGenerateCandidates_InvalidDomain(t *testing.T) {
	if _, err := GenerateCandidates("", []string{"api"}, 1, 100); err == nil {
		t.Errorf("GenerateCandidates(empty domain) = nil error, want error")
	}
}

func TestGenerateCandidates_SourceIsWordlist(t *testing.T) {
	candidates, err := GenerateCandidates("example.test", []string{"api"}, 1, 100)
	if err != nil {
		t.Fatalf("GenerateCandidates: %v", err)
	}
	if len(candidates) != 1 || candidates[0].Source != SourceWordlist {
		t.Errorf("candidate Source = %v, want %v", candidates[0].Source, SourceWordlist)
	}
}

func TestLoadWordlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "words.txt")
	content := "api\n# a comment\n\ndev\n  staging  \n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	words, err := LoadWordlist(path)
	if err != nil {
		t.Fatalf("LoadWordlist: %v", err)
	}
	want := []string{"api", "dev", "staging"}
	if len(words) != len(want) {
		t.Fatalf("LoadWordlist() = %v, want %v", words, want)
	}
	for i := range want {
		if words[i] != want[i] {
			t.Errorf("LoadWordlist()[%d] = %q, want %q", i, words[i], want[i])
		}
	}
}

func TestLoadWordlist_MissingFile(t *testing.T) {
	if _, err := LoadWordlist("/nonexistent/path/words.txt"); err == nil {
		t.Errorf("LoadWordlist(missing file) = nil error, want error")
	}
}

func assertNames(t *testing.T, candidates []SubdomainCandidate, want []string) {
	t.Helper()
	if len(candidates) != len(want) {
		got := make([]string, len(candidates))
		for i, c := range candidates {
			got[i] = c.Name
		}
		t.Fatalf("candidate names = %v, want %v", got, want)
	}
	for i, w := range want {
		if candidates[i].Name != w {
			t.Errorf("candidates[%d].Name = %q, want %q", i, candidates[i].Name, w)
		}
	}
}
