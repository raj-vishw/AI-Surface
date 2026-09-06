package ai

// DeriveConfidence computes this response's own Confidence — how sure the
// assistant is in its *interpretation*, never a probability that an
// attack occurred (phase13.md §41). Inputs are all facts already known to
// Assistant.Run by the time it derives confidence:
//
//   - factCount: how much evidence backed the structured result.
//   - truncated: whether Context evidence was cut for size (lower
//     confidence — the model saw less than exists).
//   - citationsRemoved: how many fabricated citations validation had to
//     strip from the provider's own narration (a real provider that
//     invents references is a signal its narration drifted from the
//     grounded facts, even though the final Content itself no longer
//     contains them).
//
// This is a documented heuristic, not a statistical model — exactly the
// same "no numeric confidence math should be treated as ground truth"
// discipline internal/correlation.ConfidenceForScore already applies.
func DeriveConfidence(factCount int, truncated bool, citationsRemoved int) Confidence {
	switch {
	case factCount == 0:
		return ConfidenceLow
	case citationsRemoved > 0:
		return ConfidenceLow
	case truncated:
		return ConfidenceMedium
	case factCount >= 4:
		return ConfidenceHigh
	default:
		return ConfidenceMedium
	}
}
