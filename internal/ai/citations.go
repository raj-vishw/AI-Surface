package ai

import "regexp"

// citationPattern matches exactly the bracketed "[type:id]" form
// Fact.Citation produces — phase13.md §14's worked examples
// ([event:E-102], [alert:A-45], [finding:F-20], [correlation:C-12]) use
// this same shape. Anything not matching this pattern is not a citation
// at all, just prose that happens to contain brackets.
var citationPattern = regexp.MustCompile(`\[([a-z_]+):([A-Za-z0-9._\-]+)\]`)

// ExtractCitations returns every citation-shaped token found in text, in
// order of first appearance, without deduplicating.
func ExtractCitations(text string) []string {
	matches := citationPattern.FindAllString(text, -1)
	return matches
}

// ValidateCitations checks every citation token in content against valid
// (typically Context.CitationSet()) and returns content with every
// fabricated citation removed (phase13.md §15: "if a citation does not
// exist in the supplied context, remove it") plus the list of removed
// tokens for audit/logging. A citation is never rewritten into a
// different, valid-looking one — only ever removed — so a reader can never
// be misled into trusting a fabricated reference.
func ValidateCitations(content string, valid map[string]bool) (cleaned string, removed []string) {
	seen := make(map[string]bool)
	cleaned = citationPattern.ReplaceAllStringFunc(content, func(tok string) string {
		if valid[tok] {
			return tok
		}
		if !seen[tok] {
			removed = append(removed, tok)
			seen[tok] = true
		}
		return ""
	})
	return cleaned, removed
}
