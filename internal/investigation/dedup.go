package investigation

// MergeRelationships collapses relationships sharing the same Key
// (phase9.md §39/§43's "avoid simplistic correlation" applies here too —
// a rule that fires more than once for the same pair, by construction or
// a future bug, must not silently double-count) into one, unioning
// Signals and summing... no: unlike finding merges, two rule firings for
// the exact same (source, target, type, rule) key should be identical in
// content by construction (a rule evaluates each pair once), so this is a
// safety net that simply keeps the first occurrence and logs nothing —
// there is nothing meaningful to union when the key already includes the
// rule id.
func MergeRelationships(relationships []Relationship) []Relationship {
	if len(relationships) <= 1 {
		return relationships
	}
	seen := make(map[string]bool, len(relationships))
	out := make([]Relationship, 0, len(relationships))
	for _, r := range relationships {
		key := r.Key()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, r)
	}
	return out
}
