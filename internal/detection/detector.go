package detection

import "context"

// DetectorMode declares whether a Detector performs pure passive analysis
// of already-collected evidence or may issue a single bounded safe-active
// request via Input.Fetcher (phase8.md §14).
type DetectorMode string

// Recognized detector modes.
const (
	DetectorPassive    DetectorMode = "passive"
	DetectorSafeActive DetectorMode = "safe_active"
)

// Detector analyzes one asset's already-collected Input and returns zero
// or more findings. Detect must never mutate Input, perform an unbounded
// request, brute-force a path, or manipulate any state outside its own
// return value (phase8.md §5/§15/§57). A DetectorSafeActive detector must
// still behave correctly (returning no findings, not erroring) when
// Input.Mode is ModePassive and Input.Fetcher is nil — Engine.Evaluate
// only includes it in a run when the run's Mode allows it (see registry.go
// Active), but a defensive Detector never assumes that alone.
type Detector interface {
	ID() string
	Name() string
	Description() string
	// Version identifies this detector's logic revision (phase8.md §7) —
	// bumped whenever its detection rule materially changes, so a
	// persisted Finding can record which version produced it.
	Version() int
	Category() Category
	Mode() DetectorMode
	Detect(ctx context.Context, input Input) ([]Finding, error)
}
