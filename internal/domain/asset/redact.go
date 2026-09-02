package asset

import "strings"

// redactedValue replaces any sensitive field's original value before it
// ever reaches a log line or a database row.
const redactedValue = "[REDACTED]"

// sensitiveKeyFragments are matched case-insensitively as substrings of a
// metadata key, so "Authorization", "X-Api-Key", "session_token", and
// "auth-cookie" are all caught without needing an exhaustive key list.
var sensitiveKeyFragments = []string{
	"authorization",
	"cookie",
	"password",
	"passwd",
	"secret",
	"token",
	"api_key",
	"apikey",
	"api-key",
	"access_token",
	"refresh_token",
	"private_key",
	"credential",
}

// sensitiveKeyExceptions carves out exact, deliberately-safe keys that
// would otherwise be swallowed by sensitiveKeyFragments' substring match
// — "cookie_names" legitimately contains "cookie" but, unlike every other
// key that fragment is meant to catch, its value is a list of cookie
// *names only*, never a value (phase6.md §13/§31: Phase 6's passive
// fingerprinting needs exactly this to fingerprint framework-specific
// session cookies like JSESSIONID/PHPSESSID without ever persisting what
// a cookie actually contains). This is an exact match against the key as
// a whole, never a substring — it can only narrow, never broaden, what
// isSensitiveKey catches.
var sensitiveKeyExceptions = map[string]bool{
	"cookie_names": true,
}

func isSensitiveKey(key string) bool {
	if sensitiveKeyExceptions[strings.ToLower(key)] {
		return false
	}
	lower := strings.ToLower(key)
	for _, fragment := range sensitiveKeyFragments {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	return false
}

// SanitizeMetadata returns a copy of m with every sensitive field's value
// replaced by redactedValue, recursing through nested objects and arrays.
// It is the mandatory redaction boundary between anything a discovery
// source observed and what is ever logged or persisted — callers must
// sanitize before storing or logging asset/evidence metadata, never after.
// A nil input returns nil.
func SanitizeMetadata(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for key, value := range m {
		if isSensitiveKey(key) {
			out[key] = redactedValue
			continue
		}
		out[key] = sanitizeValue(value)
	}
	return out
}

func sanitizeValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return SanitizeMetadata(val)
	case []any:
		result := make([]any, len(val))
		for i, item := range val {
			result[i] = sanitizeValue(item)
		}
		return result
	default:
		return val
	}
}
