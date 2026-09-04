package detection

import "testing"

func TestClassifyChange_New(t *testing.T) {
	change, ok := ClassifyChange("", true, true)
	if !ok || change != ChangeNew {
		t.Fatalf("expected (new, true), got (%s, %v)", change, ok)
	}
}

func TestClassifyChange_Persisting(t *testing.T) {
	change, ok := ClassifyChange(StatusOpen, true, false)
	if !ok || change != ChangePersisting {
		t.Fatalf("expected (persisting, true), got (%s, %v)", change, ok)
	}
}

func TestClassifyChange_Resolved(t *testing.T) {
	change, ok := ClassifyChange(StatusOpen, false, false)
	if !ok || change != ChangeResolved {
		t.Fatalf("expected (resolved, true), got (%s, %v)", change, ok)
	}
}

func TestClassifyChange_Reopened(t *testing.T) {
	change, ok := ClassifyChange(StatusResolved, true, false)
	if !ok || change != ChangeReopened {
		t.Fatalf("expected (reopened, true), got (%s, %v)", change, ok)
	}
}

func TestClassifyChange_SuppressedNeverChanges(t *testing.T) {
	if _, ok := ClassifyChange(StatusAcceptedRisk, true, false); ok {
		t.Fatal("expected no change reported for a suppressed finding")
	}
	if _, ok := ClassifyChange(StatusFalsePositive, false, false); ok {
		t.Fatal("expected no change reported for a false-positive finding")
	}
}
