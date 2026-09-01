// Package dns implements the DNS record and subdomain discovery engine:
// deterministic name normalization, a pluggable resolver abstraction,
// wordlist-based subdomain candidate generation, wildcard detection, and
// scope-aware bounded-concurrency DNS resolution. It never persists
// anything and never performs HTTP requests — internal/discovery/service
// (Phase 3/4's orchestration layer, extended rather than duplicated for
// Phase 5) does that.
package dns

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

// NormalizeName deterministically normalizes a DNS name: lowercased,
// trailing dot removed, each label validated. IDNA (internationalized
// domain name) labels are converted to their ASCII (punycode) form via
// idna.Lookup — the same profile used for actual DNS lookups — so
// "café.example.test" and its "xn--caf-dma.example.test" ASCII form
// normalize identically, without discarding the internationalized
// information (it's preserved in the ASCII encoding, not stripped).
//
//	"API.Example.Test."  -> "api.example.test"
func NormalizeName(name string) (string, error) {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return "", fmt.Errorf("DNS name must not be empty")
	}

	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return "", fmt.Errorf("invalid DNS name %q: %w", name, err)
	}
	ascii = strings.ToLower(ascii)

	if len(ascii) > 253 {
		return "", fmt.Errorf("DNS name %q exceeds 253 characters", name)
	}
	for _, label := range strings.Split(ascii, ".") {
		if err := validateLabel(label); err != nil {
			return "", fmt.Errorf("invalid DNS name %q: %w", name, err)
		}
	}

	return ascii, nil
}

func validateLabel(label string) error {
	if label == "" {
		return fmt.Errorf("empty label")
	}
	if len(label) > 63 {
		return fmt.Errorf("label %q exceeds 63 characters", label)
	}
	return nil
}

// JoinLabel prepends label to domain, both already-normalized, producing
// a normalized combined name — the building block subdomain candidate
// generation uses (candidate.go) rather than raw string concatenation.
func JoinLabel(label, domain string) string {
	return label + "." + domain
}
