package risk

import "testing"

func TestScorer_NoFindings_LowScore(t *testing.T) {
	s := NewScorer(DefaultWeights())
	got := s.Calculate(Input{})
	if got.Score != 0 {
		t.Errorf("expected score 0 for empty input, got %d", got.Score)
	}
	if got.Severity != SeverityLow {
		t.Errorf("expected low severity, got %s", got.Severity)
	}
	if got.ModelVersion != ModelVersion {
		t.Errorf("expected model version %s, got %s", ModelVersion, got.ModelVersion)
	}
}

func TestScorer_HighFindingPlusExposurePlusVuln_WorkedExample(t *testing.T) {
	s := NewScorer(DefaultWeights())
	got := s.Calculate(Input{
		HighestFindingSeverity:       SeverityHigh,
		HighestFindingConfidenceHigh: true,
		InternetFacing:               true,
		HighestVulnerabilityStatus:   VulnerabilityConfirmed,
		RecentChange:                 true,
	})
	// 30 (high) + 4 (confidence) + 20 (internet) + 20 (confirmed vuln) + 10 (recent change) = 84
	if got.Score != 84 {
		t.Errorf("expected score 84 matching phase10.md §41's worked example, got %d (%v)", got.Score, got.Factors)
	}
	if got.Severity != SeverityCritical {
		t.Errorf("expected Critical severity for score 84 (>=75), got %s", got.Severity)
	}
}

func TestScorer_CriticalFinding_ClampedAt100(t *testing.T) {
	s := NewScorer(DefaultWeights())
	got := s.Calculate(Input{
		HighestFindingSeverity:       SeverityCritical,
		HighestFindingConfidenceHigh: true,
		InternetFacing:               true,
		OpenServiceCount:             50, // capped by ExposureOpenServiceMax
		SensitiveEndpointCount:       10,
		ExposedAPI:                   true,
		HighestVulnerabilityStatus:   VulnerabilityConfirmed,
		IntelligenceVerdict:          IntelligenceMalicious,
		AssetCriticality:             CriticalityCritical,
		RecentChange:                 true,
	})
	if got.Score < 0 || got.Score > 100 {
		t.Fatalf("score %d out of [0,100] range", got.Score)
	}
	if got.Score != 100 {
		t.Errorf("expected clamped score of 100 given every factor firing, got %d", got.Score)
	}
	if got.Severity != SeverityCritical {
		t.Errorf("expected Critical severity, got %s", got.Severity)
	}
}

func TestScorer_LowCriticality_NegativePointsNeverProduceNegativeScore(t *testing.T) {
	s := NewScorer(DefaultWeights())
	got := s.Calculate(Input{AssetCriticality: CriticalityLow})
	if got.Score < 0 {
		t.Fatalf("score must never be negative, got %d", got.Score)
	}
}

func TestScorer_Deterministic(t *testing.T) {
	s := NewScorer(DefaultWeights())
	input := Input{HighestFindingSeverity: SeverityMedium, InternetFacing: true}
	a := s.Calculate(input)
	b := s.Calculate(input)
	if a.Score != b.Score || a.Explanation != b.Explanation {
		t.Fatalf("expected deterministic result for identical input, got %+v vs %+v", a, b)
	}
}

func TestScorer_ExplanationNonEmpty(t *testing.T) {
	s := NewScorer(DefaultWeights())
	got := s.Calculate(Input{HighestFindingSeverity: SeverityLow})
	if got.Explanation == "" {
		t.Fatal("expected non-empty explanation")
	}
	empty := s.Calculate(Input{})
	if empty.Explanation == "" {
		t.Fatal("expected non-empty explanation even with zero factors")
	}
}

func TestScorer_RiskIsNotVulnerabilityConfirmation(t *testing.T) {
	// A probable (not confirmed) match must score strictly less than a
	// confirmed one, and neither status alone should saturate the score —
	// risk is combined context, never a vulnerability-confirmed claim
	// (phase10.md §35).
	s := NewScorer(DefaultWeights())
	probable := s.Calculate(Input{HighestVulnerabilityStatus: VulnerabilityProbable})
	confirmed := s.Calculate(Input{HighestVulnerabilityStatus: VulnerabilityConfirmed})
	if probable.Score >= confirmed.Score {
		t.Fatalf("expected probable (%d) < confirmed (%d)", probable.Score, confirmed.Score)
	}
}

func TestSeverityForScore_Boundaries(t *testing.T) {
	cases := []struct {
		score int
		want  Severity
	}{
		{0, SeverityLow}, {24, SeverityLow}, {25, SeverityMedium}, {49, SeverityMedium},
		{50, SeverityHigh}, {74, SeverityHigh}, {75, SeverityCritical}, {100, SeverityCritical},
	}
	for _, c := range cases {
		if got := SeverityForScore(c.score); got != c.want {
			t.Errorf("SeverityForScore(%d) = %s, want %s", c.score, got, c.want)
		}
	}
}
