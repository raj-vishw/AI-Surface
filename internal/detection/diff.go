package detection

// ChangeType classifies one finding identity's relationship between "the
// state immediately before this detection run" and "this run's result"
// (phase8.md §75's RESOLVED/PERSISTING/NEW and §76's baseline
// new/existing/resolved/reopened — the same four-way classification,
// unified: ChangePersisting is §76's "existing").
type ChangeType string

// Recognized change types.
const (
	ChangeNew        ChangeType = "new"
	ChangePersisting ChangeType = "persisting"
	ChangeResolved   ChangeType = "resolved"
	ChangeReopened   ChangeType = "reopened"
)

// ClassifyChange derives a finding identity's ChangeType from its
// pre-run status and whether this run detected it, mirroring NextStatus's
// same transition table but naming the *event* rather than the resulting
// state (a resolved->reopened transition is both "status = reopened" and
// "change = reopened", but a open->open transition is "status = open"
// and "change = persisting", not merely silence). ok is false when
// nothing changed and no event is worth recording (e.g. a suppressed
// finding that stays suppressed).
func ClassifyChange(previous Status, currentlyDetected, created bool) (ChangeType, bool) {
	switch previous {
	case "":
		if currentlyDetected {
			return ChangeNew, true
		}
		return "", false
	case StatusResolved:
		if currentlyDetected {
			return ChangeReopened, true
		}
		return "", false
	case StatusOpen, StatusReopened:
		if currentlyDetected {
			if created {
				return ChangeNew, true
			}
			return ChangePersisting, true
		}
		return ChangeResolved, true
	case StatusAcceptedRisk, StatusFalsePositive:
		return "", false
	default:
		return "", false
	}
}
