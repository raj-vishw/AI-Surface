package dns

import (
	"regexp"
	"strings"
)

// txtSecretFragments mirror internal/domain/asset's sensitive-key
// vocabulary (that package's list is unexported, so this is a small,
// intentionally-consistent parallel list, not a reuse) — but applied here
// to *content* inside a free-form TXT record value, not to a metadata
// map's keys. TXT records are unstructured text (phase5.md §16), so the
// generic key-based internal/domain/asset.SanitizeMetadata redaction (which
// only inspects map keys) cannot catch a secret embedded inside the text
// itself — e.g. a TXT record whose entire value is
// "api_key=sk-live-abc123" has exactly one map key ("value"), which isn't
// sensitive-looking at all.
var txtSecretFragments = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey",
	"api-key", "access_token", "refresh_token", "private_key", "credential",
	"authorization",
}

// txtKeyValuePattern matches "key=value" or "key: value" pairs (the shape
// most TXT-embedded secrets take — verification tokens, API keys) so only
// the value half is redacted, preserving the record's overall structure
// (an SPF/DMARC record's legitimate "v=spf1 -all" is untouched, since "v"
// never matches txtSecretFragments).
var txtKeyValuePattern = regexp.MustCompile(`(?i)([\w.-]+)\s*[:=]\s*(\S+)`)

// SanitizeTXTValue redacts any "key=value"/"key: value" pair within value
// whose key matches a known secret-fragment pattern, replacing only the
// value half with "[REDACTED]" — the same redactedValue text
// internal/domain/asset.SanitizeMetadata uses, for one consistent
// redaction marker across the whole platform. Call this before a TXT
// record's Value ever leaves the resolver (see parseAnswers) — the
// mandatory boundary between an observed record and anything logged or
// persisted (phase5.md §16).
func SanitizeTXTValue(value string) string {
	return txtKeyValuePattern.ReplaceAllStringFunc(value, func(match string) string {
		parts := txtKeyValuePattern.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		key, sep := parts[1], match[len(parts[1]):len(match)-len(parts[2])]
		if !isSensitiveTXTKey(key) {
			return match
		}
		return key + sep + "[REDACTED]"
	})
}

func isSensitiveTXTKey(key string) bool {
	lower := strings.ToLower(key)
	for _, fragment := range txtSecretFragments {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	return false
}
