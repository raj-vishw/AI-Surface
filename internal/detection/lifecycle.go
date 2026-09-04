package detection

// Status mirrors internal/domain/finding.Status's lifecycle vocabulary —
// a distinct type for the same self-contained-engine reason every type in
// this package is (phase8.md §4).
type Status string

// Recognized finding statuses.
const (
	StatusOpen          Status = "open"
	StatusResolved      Status = "resolved"
	StatusReopened      Status = "reopened"
	StatusAcceptedRisk  Status = "accepted_risk"
	StatusFalsePositive Status = "false_positive"
)

// NextStatus computes the lifecycle transition for a finding identity
// given its previous status and whether this run detected it again
// (phase8.md §4's worked example: OPEN -> RESOLVED -> REOPENED).
// StatusAcceptedRisk and StatusFalsePositive are sticky: a detector
// re-observing a suppressed condition does not silently reopen it — a
// human decision stays in force until explicitly changed via
// internal/service/detection.OverrideStatus (phase8.md §77's "do not
// automatically suppress... unless the existing policy explicitly
// supports that" — this project's policy is "never automatically", the
// conservative default).
func NextStatus(previous Status, currentlyDetected bool) Status {
	switch previous {
	case "":
		return StatusOpen
	case StatusResolved:
		if currentlyDetected {
			return StatusReopened
		}
		return StatusResolved
	case StatusOpen, StatusReopened:
		if currentlyDetected {
			return previous
		}
		return StatusResolved
	case StatusAcceptedRisk, StatusFalsePositive:
		return previous
	default:
		if currentlyDetected {
			return StatusOpen
		}
		return previous
	}
}
