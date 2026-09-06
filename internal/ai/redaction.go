package ai

import "regexp"

// secretPatterns are deliberately conservative, high-signal patterns for
// values that must never reach a prompt or be persisted (phase13.md §5/
// §64/§86): API keys, bearer tokens, common cloud credential shapes,
// passwords/secrets embedded in text, private key blocks, and cookie/
// session-header values. This is a documented, best-effort heuristic —
// like internal/discovery/endpoint's own SensitiveParameters matching, it
// is not a claim of perfect secret detection, only a mandatory first line
// of defense applied to every Fact before it is ever included in a
// Context.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._\-]{10,}`),
	regexp.MustCompile(`(?i)\b(api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|secret|client[_-]?secret)\s*[:=]\s*['"]?[a-z0-9._\-]{8,}['"]?`),
	regexp.MustCompile(`(?i)\bpassword\s*[:=]\s*\S+`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),            // AWS access key id
	regexp.MustCompile(`(?i)\bsk-[a-z0-9]{16,}\b`),        // OpenAI-style secret key
	regexp.MustCompile(`(?i)\bgh[pousr]_[a-z0-9]{20,}\b`), // GitHub token
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)\b(set-)?cookie\s*[:=]\s*\S+`),
	regexp.MustCompile(`\b[a-zA-Z0-9\-_]{20,}\.[a-zA-Z0-9\-_]{10,}\.[a-zA-Z0-9\-_]{10,}\b`), // JWT-shaped
}

const redactedPlaceholder = "[REDACTED]"

// Redact replaces any recognized secret-shaped substring in s with a fixed
// placeholder. It never partially redacts (leaking a prefix/suffix) and
// never logs or returns the original match.
func Redact(s string) string {
	for _, re := range secretPatterns {
		s = re.ReplaceAllString(s, redactedPlaceholder)
	}
	return s
}

// RedactFact returns a copy of f with Summary and every Attributes value
// redacted — the mandatory boundary every Fact crosses before entering a
// Context (phase13.md §5/§86: "before sending context externally: redact
// secrets").
func RedactFact(f Fact) Fact {
	out := f
	out.Summary = Redact(f.Summary)
	if len(f.Attributes) > 0 {
		attrs := make(map[string]string, len(f.Attributes))
		for k, v := range f.Attributes {
			attrs[k] = Redact(v)
		}
		out.Attributes = attrs
	}
	return out
}
