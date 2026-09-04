package endpoint

// This file implements path-parameter templating (phase7.md §38) —
// layered on top of, never duplicating, internal/domain/endpoint.
// Normalize, which already handles hostname casing, default ports, dot
// segments, trailing slash, fragment removal, and query-parameter-name-
// only retention (phase7.md §7/§8/§9 are already fully satisfied by that
// existing function; see docs/architecture/endpoint-discovery.md).

import (
	"regexp"
	"strings"
)

var (
	// numericSegmentPattern: a path segment consisting entirely of digits
	// — a conservative, high-confidence dynamic-ID signal ("/users/123").
	numericSegmentPattern = regexp.MustCompile(`^[0-9]+$`)
	// uuidSegmentPattern: a canonical (hyphenated) UUID.
	uuidSegmentPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	// opaqueTokenPattern: a long (20+ character), alphanumeric-with-{_,-}
	// segment — long enough that it's very unlikely to be an ordinary
	// path word ("admin", "settings", ...) and requires at least one
	// digit, so purely-alphabetic words like "dashboard" or
	// "administration" are never mistaken for an opaque identifier.
	opaqueTokenPattern  = regexp.MustCompile(`^[0-9a-zA-Z_-]{20,}$`)
	opaqueTokenHasDigit = regexp.MustCompile(`[0-9]`)
)

// PathParamPlaceholder is the templated form a detected dynamic segment
// is replaced with.
const PathParamPlaceholder = "{id}"

// TemplatePath replaces conservatively-detected dynamic segments in path
// with PathParamPlaceholder, so "/users/123" and "/users/456" collapse to
// the same logical endpoint "/users/{id}" (phase7.md §38) while
// "/users/admin" is left untouched — a plain word is never treated as a
// dynamic identifier without much stronger evidence than this package
// currently has (phase7.md §76's explicit non-goal).
func TemplatePath(path string) string {
	segments := strings.Split(path, "/")
	changed := false
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		if isDynamicSegment(seg) {
			segments[i] = PathParamPlaceholder
			changed = true
		}
	}
	if !changed {
		return path
	}
	return strings.Join(segments, "/")
}

func isDynamicSegment(seg string) bool {
	if numericSegmentPattern.MatchString(seg) {
		return true
	}
	if uuidSegmentPattern.MatchString(seg) {
		return true
	}
	if opaqueTokenPattern.MatchString(seg) && opaqueTokenHasDigit.MatchString(seg) {
		return true
	}
	return false
}
