package detection

// Confidence answers "how confident are we that this finding is actually
// present?" — in [0.0, 1.0], independent of Severity (phase8.md §12).
type Confidence float64

// Confidence level boundaries (phase8.md §12's five-bucket model).
const (
	thresholdLow      = 0.20
	thresholdMedium   = 0.45
	thresholdHigh     = 0.70
	thresholdVeryHigh = 0.90
)

// Level names a bucketed Confidence value.
type Level string

// Recognized confidence levels, very_low to very_high.
const (
	LevelVeryLow  Level = "very_low"
	LevelLow      Level = "low"
	LevelMedium   Level = "medium"
	LevelHigh     Level = "high"
	LevelVeryHigh Level = "very_high"
)

// Level buckets c into a named confidence level.
func (c Confidence) Level() Level {
	switch {
	case c < 0 || c > 1:
		return LevelVeryLow
	case c >= thresholdVeryHigh:
		return LevelVeryHigh
	case c >= thresholdHigh:
		return LevelHigh
	case c >= thresholdMedium:
		return LevelMedium
	case c >= thresholdLow:
		return LevelLow
	default:
		return LevelVeryLow
	}
}

// Clamp returns c bounded to [0.0, 1.0] — used when combining/averaging
// confidence contributions to guarantee the result is always a valid
// Confidence, never relying on every call site to check by hand.
func (c Confidence) Clamp() Confidence {
	switch {
	case c < 0:
		return 0
	case c > 1:
		return 1
	default:
		return c
	}
}
