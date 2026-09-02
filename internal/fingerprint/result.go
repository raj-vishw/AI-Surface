package fingerprint

// Signal is one concrete piece of matched evidence at evaluation time —
// the engine's live counterpart to internal/domain/fingerprint.Signal
// (identical shape, deliberately not the same Go type — see this
// package's doc comment). Produced by the matcher, consumed by the
// scorer and by --explain output.
type Signal struct {
	Type        SignalType
	Field       string
	Value       string
	Weight      float64
	Description string
}

// key returns the (Type, Field, Value) identity used to deduplicate
// identical evidence (phase6.md §9: "Server: nginx appearing three times
// must not become 0.90 + 0.90 + 0.90").
func (s Signal) key() string {
	return string(s.Type) + "|" + s.Field + "|" + s.Value
}

// Result is one signature's final, scored match against an
// Observation — the engine's output unit, before internal/service/
// fingerprint translates it into a persisted internal/domain/fingerprint.
// Fingerprint + Evidence pair.
type Result struct {
	SignatureName string // the signature's declared Name, pre-normalization
	Category      Category
	Technology    string // normalized via NormalizeTechnology
	Product       string
	Vendor        string
	Version       string // "" unless explicitly extracted (phase6.md §12) — never guessed

	Confidence float64
	Level      Level

	// Signals are every matched signal (deduplicated), in declaration
	// order — the complete explanation for this result (phase6.md §42).
	Signals []Signal
}
