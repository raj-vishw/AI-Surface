package ai

import (
	"regexp"
	"strings"
)

// injectionMarkers are phrases commonly used in prompt-injection attempts
// embedded in untrusted telemetry (phase13.md §35/§63) — log messages,
// URLs, usernames, process names, HTTP responses, alert/intelligence
// descriptions. This is used only to flag/log suspicious telemetry for
// analyst visibility; it never censors the underlying Fact, and it is
// never itself sufficient defense — the actual defense is structural:
// untrusted content is always wrapped in an explicit DATA block in the
// prompt (see BuildPrompt) that the system prompt instructs the model to
// never treat as instructions, regardless of what it says.
var injectionMarkers = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore (all |the )?(previous|prior|above) instructions`),
	regexp.MustCompile(`(?i)disregard (all |the )?(previous|prior|above)`),
	regexp.MustCompile(`(?i)reveal (the |your )?(credentials|api key|password|secret|system prompt)`),
	regexp.MustCompile(`(?i)you are now`),
	regexp.MustCompile(`(?i)new instructions?:`),
	regexp.MustCompile(`(?i)execute (this|the following) command`),
}

// ContainsInjectionAttempt reports whether s contains a recognized
// prompt-injection marker — used for audit logging and tests, never as a
// content filter (phase13.md §35's test category exercises exactly this
// function).
func ContainsInjectionAttempt(s string) bool {
	for _, re := range injectionMarkers {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// unsupportedClaimPatterns flag overconfident, unhedged language a
// generated response must never contain unattributed to evidence
// (phase13.md §17/§43): flat assertions of attacker action/identity/intent
// rather than "the evidence is consistent with...". Matched case-
// insensitively against generated Content only — never against Context
// facts, which are the platform's own already-qualified observations.
var unsupportedClaimPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bthe attacker (is|was|did|has|used|compromised|exploited)\b`),
	regexp.MustCompile(`(?i)\bconfirmed attack\b`),
	regexp.MustCompile(`(?i)\b(definitely|certainly|undoubtedly) (compromised|malicious|an attack)\b`),
	regexp.MustCompile(`(?i)\bthreat actor (is|was) (from|located in|based in|affiliated with)\b`),
	regexp.MustCompile(`(?i)\b(nation-state|state-sponsored) actor\b`),
}

// cautiousReplacement is the fixed, hedged substitute phrase used when an
// unsupported-claim pattern is found (phase13.md §17's own worked
// example: "prefer 'the available evidence is consistent with X, but does
// not establish X conclusively'"). Rewriting to one fixed, honest phrase
// — rather than attempting to preserve the claim's specifics — is a
// deliberate, conservative choice: a fabricated specific can't be
// "softened" into a true one.
const cautiousReplacement = "the available evidence is consistent with this, but does not establish it conclusively"

// RewriteUnsupportedClaims scans content for unhedged, unsupported-claim
// language and replaces each match with cautiousReplacement, returning the
// rewritten text and how many replacements were made (for audit logging
// and tests).
func RewriteUnsupportedClaims(content string) (rewritten string, count int) {
	rewritten = content
	for _, re := range unsupportedClaimPatterns {
		rewritten = re.ReplaceAllStringFunc(rewritten, func(_ string) string {
			count++
			return cautiousReplacement
		})
	}
	return rewritten, count
}

// AttributionPatterns are checked separately from unsupportedClaimPatterns
// because attribution (phase13.md §18) is never permitted at all in this
// phase's output, hedged or not — "the AI must not infer threat actor
// identity, nationality, organization, or motive". ContainsAttribution is
// used by validation.go to reject rather than rewrite such content.
var attributionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(threat actor|attacker)('s)? (nationality|motive|organization|identity) (is|appears to be|was)\b`),
	regexp.MustCompile(`(?i)\bAPT[- ]?\d+\b`),
	regexp.MustCompile(`(?i)\b(this|the) (attack|activity) (is|was) (attributed|linked) to\b`),
}

// ContainsAttribution reports whether s asserts threat-actor attribution.
func ContainsAttribution(s string) bool {
	for _, re := range attributionPatterns {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// wrapUntrusted frames one piece of untrusted telemetry as inert data
// inside a prompt (phase13.md §36/§37) — used by prompt.go when embedding
// Fact summaries that ultimately trace back to attacker-influenceable
// strings (a hostname, a URL, an HTTP response snippet, an intelligence
// description).
func wrapUntrusted(label, s string) string {
	var b strings.Builder
	b.WriteString("<data source=\"")
	b.WriteString(label)
	b.WriteString("\">\n")
	b.WriteString(s)
	b.WriteString("\n</data>")
	return b.String()
}
