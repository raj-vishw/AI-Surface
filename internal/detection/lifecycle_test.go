package detection

import "testing"

func TestNextStatus_WorkedExample(t *testing.T) {
	// phase8.md §4's worked example: OPEN -> RESOLVED -> REOPENED.
	scan1 := NextStatus("", true)
	if scan1 != StatusOpen {
		t.Fatalf("scan 1: expected OPEN, got %s", scan1)
	}
	scan2 := NextStatus(scan1, false)
	if scan2 != StatusResolved {
		t.Fatalf("scan 2: expected RESOLVED, got %s", scan2)
	}
	scan3 := NextStatus(scan2, true)
	if scan3 != StatusReopened {
		t.Fatalf("scan 3: expected REOPENED, got %s", scan3)
	}
}

func TestNextStatus_StaysOpenWhilePersisting(t *testing.T) {
	if got := NextStatus(StatusOpen, true); got != StatusOpen {
		t.Fatalf("expected OPEN to stay OPEN, got %s", got)
	}
	if got := NextStatus(StatusReopened, true); got != StatusReopened {
		t.Fatalf("expected REOPENED to stay REOPENED, got %s", got)
	}
}

func TestNextStatus_SuppressedStaysSticky(t *testing.T) {
	if got := NextStatus(StatusAcceptedRisk, true); got != StatusAcceptedRisk {
		t.Fatalf("expected accepted_risk to stay sticky when re-detected, got %s", got)
	}
	if got := NextStatus(StatusFalsePositive, false); got != StatusFalsePositive {
		t.Fatalf("expected false_positive to stay sticky when not detected, got %s", got)
	}
}

func TestNextStatus_ResolvedStaysResolvedWhenNotDetected(t *testing.T) {
	if got := NextStatus(StatusResolved, false); got != StatusResolved {
		t.Fatalf("expected resolved to stay resolved, got %s", got)
	}
}
