package fingerprint

import "testing"

func TestScore_SingleSignal(t *testing.T) {
	declared := []compiledSignal{{rule: SignalRule{Weight: 0.8}}}
	matched := []Signal{{Type: "http_header", Field: "Server", Value: "nginx", Weight: 0.8}}
	got := score(matched, declared)
	if got != 1.0 {
		t.Errorf("score() = %v, want 1.0 (the only declared signal matched)", got)
	}
}

func TestScore_PartialMatch(t *testing.T) {
	declared := []compiledSignal{
		{rule: SignalRule{Weight: 0.6}},
		{rule: SignalRule{Weight: 0.4}},
	}
	matched := []Signal{{Type: "a", Field: "x", Value: "y", Weight: 0.6}}
	got := score(matched, declared)
	want := 0.6
	if got != want {
		t.Errorf("score() = %v, want %v", got, want)
	}
}

func TestScore_DuplicateSignalNotDoubleCounted(t *testing.T) {
	declared := []compiledSignal{{rule: SignalRule{Weight: 0.9}}}
	s := Signal{Type: "http_header", Field: "Server", Value: "nginx", Weight: 0.9}
	matched := []Signal{s, s, s} // the same signal three times
	got := score(matched, declared)
	if got != 1.0 {
		t.Errorf("score() = %v, want 1.0 — duplicate identical evidence must not sum past the declared maximum", got)
	}
}

func TestScore_NoDeclaredSignals(t *testing.T) {
	if got := score(nil, nil); got != 0 {
		t.Errorf("score(no declared signals) = %v, want 0", got)
	}
}

func TestScore_NeverExceedsOne(t *testing.T) {
	declared := []compiledSignal{{rule: SignalRule{Weight: 0.5}}}
	// Two distinct matched signals somehow summing past the single
	// declared weight (shouldn't happen via the matcher, but the scorer
	// itself must still clip defensively).
	matched := []Signal{
		{Type: "a", Field: "1", Value: "x", Weight: 0.5},
		{Type: "b", Field: "2", Value: "y", Weight: 0.8},
	}
	got := score(matched, declared)
	if got > 1.0 {
		t.Errorf("score() = %v, must never exceed 1.0", got)
	}
}

func TestThresholds_Level(t *testing.T) {
	tests := []struct {
		score float64
		want  Level
	}{
		{0.0, LevelWeak}, {0.29, LevelWeak},
		{0.30, LevelLow}, {0.59, LevelLow},
		{0.60, LevelMedium}, {0.79, LevelMedium},
		{0.80, LevelHigh}, {0.94, LevelHigh},
		{0.95, LevelVeryHigh}, {1.0, LevelVeryHigh},
	}
	for _, tc := range tests {
		if got := DefaultThresholds.Level(tc.score); got != tc.want {
			t.Errorf("Level(%v) = %s, want %s", tc.score, got, tc.want)
		}
	}
}

func TestThresholds_Validate(t *testing.T) {
	if err := (Thresholds{}).Validate(); err != nil {
		t.Errorf("zero-value Thresholds should be valid (means defaults), got: %v", err)
	}
	if err := DefaultThresholds.Validate(); err != nil {
		t.Errorf("DefaultThresholds should be valid, got: %v", err)
	}
	bad := Thresholds{Low: 0.5, Medium: 0.3, High: 0.8, VeryHigh: 0.95} // not increasing
	if err := bad.Validate(); err == nil {
		t.Error("expected an error for non-increasing thresholds")
	}
}

func TestThresholds_CustomConfiguration(t *testing.T) {
	custom := Thresholds{Low: 0.1, Medium: 0.2, High: 0.3, VeryHigh: 0.4}
	if got := custom.Level(0.25); got != LevelMedium {
		t.Errorf("custom Thresholds.Level(0.25) = %s, want medium", got)
	}
}
