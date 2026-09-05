package ruleengine

import (
	"context"
	"strconv"
)

// TestCase is one fixture a rule definition is checked against
// (phase11.md §48) — entirely in-memory, synthetic, never real sensitive
// data (phase11.md §51).
type TestCase struct {
	Name             string
	Events           []Event
	ExpectMatchCount int
	ExpectSeverity   Severity // "" means don't check
}

// TestCaseResult is one TestCase's outcome.
type TestCaseResult struct {
	Name    string
	Passed  bool
	Matches []Match
	Reason  string // set when Passed is false
}

// TestReport is RunTest's full result (phase11.md §49's CLI output
// shape).
type TestReport struct {
	Passed  bool
	Results []TestCaseResult
}

// RunTest validates+compiles def once, then evaluates it against every
// case (phase11.md §48/§49) — no alert or persistent match is ever
// created by RunTest (phase11.md §56: a rule test is always a dry run).
// Living in this engine package (rather than the service layer) keeps
// the test harness usable with zero database dependency — exactly what
// internal/ruleengine/builtin's own regression tests need.
func RunTest(def Definition, cases []TestCase) (TestReport, error) {
	compiled, err := Compile(def)
	if err != nil {
		return TestReport{}, err
	}

	engine := NewEngine()
	report := TestReport{Passed: true}
	for _, tc := range cases {
		matches, err := engine.Evaluate(context.Background(), compiled, tc.Events)
		result := TestCaseResult{Name: tc.Name, Matches: matches}

		switch {
		case err != nil:
			result.Reason = err.Error()
		case len(matches) != tc.ExpectMatchCount:
			result.Reason = formatCountMismatch(tc.ExpectMatchCount, len(matches))
		case tc.ExpectSeverity != "" && len(matches) > 0 && matches[0].Severity != tc.ExpectSeverity:
			result.Reason = formatSeverityMismatch(tc.ExpectSeverity, matches[0].Severity)
		default:
			result.Passed = true
		}

		if !result.Passed {
			report.Passed = false
		}
		report.Results = append(report.Results, result)
	}
	return report, nil
}

func formatCountMismatch(expected, actual int) string {
	return "expected " + strconv.Itoa(expected) + " match(es), got " + strconv.Itoa(actual)
}

func formatSeverityMismatch(expected, actual Severity) string {
	return "expected severity " + string(expected) + ", got " + string(actual)
}
