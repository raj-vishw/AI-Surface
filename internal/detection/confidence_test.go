package detection

import "testing"

func TestConfidence_Level(t *testing.T) {
	cases := []struct {
		c    Confidence
		want Level
	}{
		{0.0, LevelVeryLow}, {0.30, LevelLow}, {0.50, LevelMedium},
		{0.75, LevelHigh}, {0.95, LevelVeryHigh}, {1.0, LevelVeryHigh},
	}
	for _, tc := range cases {
		if got := tc.c.Level(); got != tc.want {
			t.Errorf("Confidence(%.2f).Level() = %s, want %s", tc.c, got, tc.want)
		}
	}
}

func TestConfidence_Clamp(t *testing.T) {
	if Confidence(1.5).Clamp() != 1.0 {
		t.Error("expected 1.5 clamped to 1.0")
	}
	if Confidence(-0.5).Clamp() != 0.0 {
		t.Error("expected -0.5 clamped to 0.0")
	}
	if Confidence(0.5).Clamp() != 0.5 {
		t.Error("expected in-range value unchanged")
	}
}

func TestSeverity_Rank(t *testing.T) {
	if SeverityCritical.Rank() <= SeverityHigh.Rank() {
		t.Fatal("critical must outrank high")
	}
	if SeverityInformational.Rank() != 0 {
		t.Fatalf("expected informational rank 0, got %d", SeverityInformational.Rank())
	}
	if Severity("bogus").Rank() != -1 {
		t.Fatal("expected unrecognized severity to rank -1")
	}
}

func TestTruncateExcerpt(t *testing.T) {
	if got := TruncateExcerpt("short", 100); got != "short" {
		t.Errorf("expected short string unchanged, got %q", got)
	}
	long := "abcdefghij"
	got := TruncateExcerpt(long, 5)
	if got != "abcde...[truncated]" {
		t.Errorf("unexpected truncation result: %q", got)
	}
}

func TestConfig_DetectorEnabled(t *testing.T) {
	cfg := Config{}
	if !cfg.DetectorEnabled("anything") {
		t.Fatal("expected nil Detectors map to mean everything enabled")
	}
	cfg.Detectors = map[string]bool{"a": false}
	if cfg.DetectorEnabled("a") {
		t.Fatal("expected explicit false to disable")
	}
	if !cfg.DetectorEnabled("b") {
		t.Fatal("expected absent key to default to enabled")
	}
}
