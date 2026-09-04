package endpoint

import "regexp"

// graphQLClientPattern recognizes common GraphQL client library references
// in JavaScript source (phase7.md §18's "JavaScript GraphQL client
// references") — used only to raise confidence when a /graphql path is
// also referenced nearby in the same source; never used to actively query
// anything (phase7.md §18: "do not perform arbitrary GraphQL queries...
// do not attempt introspection").
var graphQLClientPattern = regexp.MustCompile(`(?i)\b(apollo-?client|graphql-request|urql|relay)\b|\bgql\s*` + "`")

// ReferencesGraphQLClient reports whether source appears to use a
// GraphQL client library — a corroborating signal only, never itself
// sufficient to classify an endpoint (that requires an actual /graphql
// path match — see Classify).
func ReferencesGraphQLClient(source string) bool {
	return graphQLClientPattern.MatchString(source)
}
