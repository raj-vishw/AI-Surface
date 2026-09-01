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

func isSensitiveKey(key string) bool {
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
