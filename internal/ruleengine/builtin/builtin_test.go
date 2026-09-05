package builtin

import (
	"testing"

	"ai-recon-platform/internal/ruleengine"
)

// TestAll_EveryBuiltinRulePassesItsOwnRegressionSuite is the baseline
// every built-in rule must pass before being enabled (phase11.md §119):
// compiles cleanly, is fully documented, and passes its own positive/
// negative/boundary test cases (phase11.md §52).
func TestAll_EveryBuiltinRulePassesItsOwnRegressionSuite(t *testing.T) {
	for _, r := range All() {
		t.Run(r.Name, func(t *testing.T) {
			if _, err := ruleengine.Compile(r.Definition); err != nil {
				t.Fatalf("built-in rule %q failed to compile: %v", r.Name, err)
			}
			if r.Purpose == "" || r.Logic == "" || len(r.FalsePositives) == 0 {
				t.Errorf("built-in rule %q is missing required documentation (purpose/logic/false-positive guidance)", r.Name)
			}
			if len(r.Tests) < 2 {
				t.Fatalf("built-in rule %q must carry at least a positive and a negative test case", r.Name)
			}

			report, err := ruleengine.RunTest(r.Definition, r.Tests)
			if err != nil {
				t.Fatalf("RunTest: %v", err)
			}
			if !report.Passed {
				for _, res := range report.Results {
					if !res.Passed {
						t.Errorf("case %q failed: %s", res.Name, res.Reason)
					}
				}
			}
		})
	}
}
