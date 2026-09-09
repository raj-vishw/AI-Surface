package ai

import (
	"sort"
	"strconv"
)

// chronological returns facts sorted oldest-first, stable — the order
// every Observed/Inferred narrative is built in (phase13.md §19's
// "timeline" section, and §24's "chronological summary").
func chronological(facts []Fact) []Fact {
	out := make([]Fact, len(facts))
	copy(out, facts)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Timestamp.Before(out[j].Timestamp) })
	return out
}

// observeOrInfer routes one fact into a StructuredResult's Observed or
// Inferred section by its own recorded Provenance — the same
// observed-vs-inferred distinction internal/correlation.Provenance
// already establishes for edges, applied uniformly across every fact type
// here (phase13.md §16).
func observeOrInfer(r *StructuredResult, f Fact) {
	statement := string(f.Type) + ": " + f.Summary
	if f.Provenance == ProvenanceInferred {
		r.infer(statement, f.Citation())
		return
	}
	r.observe(statement, f.Citation())
}

// coverage describes one category of evidence a thorough investigation of
// a given task would ideally have, and why its absence matters
// (phase13.md §25). Deliberately a fixed, documented table — never
// invented per-context.
type coverage struct {
	types   []FactType
	label   string
	because string
}

var investigationCoverage = []coverage{
	{[]FactType{FactAlert, FactDetection}, "detections or alerts", "without at least one detection or alert, there is no triggering signal to explain the investigation's existence"},
	{[]FactType{FactFinding}, "findings", "findings ground an investigation in a specific, already-verified condition rather than raw signal alone"},
	{[]FactType{FactAsset}, "asset context", "without asset context, it is unclear what was actually affected or how exposed it is"},
	{[]FactType{FactCorrelation, FactEdge}, "cross-signal correlation", "without correlation, related activity elsewhere in the environment may be missed"},
	{[]FactType{FactIntelligence}, "threat intelligence", "without intelligence context, indicators here cannot be checked against known-bad reputation"},
	{[]FactType{FactTimelineEvent}, "a recorded timeline", "without a timeline, the sequence and pacing of events cannot be assessed"},
}

// evidenceGaps compares which FactTypes ctx actually contains against
// investigationCoverage and returns one explanatory line per missing
// category (phase13.md §25) — it never fabricates what the missing
// evidence would say, only that it is absent and why that matters.
func evidenceGaps(ctx Context) []string {
	var gaps []string
	for _, c := range investigationCoverage {
		if !hasAny(ctx, c.types...) {
			gaps = append(gaps, "No "+c.label+" is present — "+c.because+".")
		}
	}
	return gaps
}

func hasAny(ctx Context, types ...FactType) bool {
	for _, t := range types {
		if ctx.HasType(t) {
			return true
		}
	}
	return false
}

// baseUnknowns are the things this platform's evidence model can never by
// itself establish, regardless of how much evidence exists — always
// listed, never inferred away by the presence of related evidence
// (phase13.md §16's own worked example: "Unknown: whether the credentials
// were compromised" is listed even though a login succeeded).
func baseUnknowns(ctx Context) []string {
	unknowns := []string{
		"Whether any observed activity reflects malicious intent, as opposed to legitimate but unusual behavior.",
		"The identity, motive, or organizational affiliation of any responsible party — this platform never infers attribution.",
	}
	if hasAny(ctx, FactAlert, FactDetection, FactFinding) {
		unknowns = append(unknowns, "Whether any credentials, accounts, or systems referenced above were actually compromised, absent direct confirming evidence.")
	}
	return unknowns
}

// GenerateInvestigationQuestions returns evidence-gap-driven questions an
// analyst could ask next (phase13.md §26) — always tied to what is
// actually missing or present, never generic filler unconnected to the
// evidence.
func GenerateInvestigationQuestions(ctx Context) []string {
	var qs []string
	if !hasAny(ctx, FactAsset) {
		qs = append(qs, "Which asset was affected by the activity described above?")
	}
	if hasAny(ctx, FactAlert) && !hasAny(ctx, FactCorrelation, FactEdge) {
		qs = append(qs, "Is there related activity elsewhere in the environment that a correlation pass would surface?")
	}
	if hasAny(ctx, FactDetection) && !hasAny(ctx, FactIntelligence) {
		qs = append(qs, "Do any indicators involved (IP, hostname, domain) have a known reputation in threat intelligence?")
	}
	if hasAny(ctx, FactFinding) && !hasAny(ctx, FactTimelineEvent) {
		qs = append(qs, "What is the full chronological sequence of events surrounding this finding?")
	}
	if hasAny(ctx, FactAlert, FactDetection) {
		qs = append(qs, "Is this activity consistent with the affected asset's normal baseline behavior?")
	}
	if hasAny(ctx, FactCorrelation) {
		qs = append(qs, "Does the correlated activity form a coherent sequence, or could these observations be independently explained?")
	}
	if len(qs) == 0 {
		qs = append(qs, "What additional evidence would most reduce uncertainty about this activity?")
	}
	return qs
}

// nextSteps produces read-only suggestions, never an executable action
// (phase13.md §27) — always phrased as something an analyst does, never
// something this platform does automatically.
func nextSteps(ctx Context) []string {
	steps := []string{"Review each cited item above directly in ai-surface before drawing conclusions."}
	if hasAny(ctx, FactAlert, FactDetection) && !hasAny(ctx, FactCorrelation) {
		steps = append(steps, "Run ai-surface correlation evaluate for this target to check for related activity.")
	}
	if !hasAny(ctx, FactIntelligence) {
		steps = append(steps, "Review threat intelligence for any indicators (IP, hostname, domain) involved.")
	}
	if hasAny(ctx, FactCorrelation) && !hasAny(ctx, FactAttackChain) {
		steps = append(steps, "Inspect the correlation's attack chain, if one was generated, for a staged narrative of the activity.")
	}
	steps = append(steps, "Compare the affected asset's activity against its established baseline, if one exists.")
	return steps
}

// SummarizeInvestigation builds the deterministic structured summary
// phase13.md §19 specifies: executive summary, observations, timeline,
// affected assets, alerts/findings, intelligence context, uncertainty, and
// next steps — all derived from ctx's facts, never invented.
func SummarizeInvestigation(ctx Context) StructuredResult {
	var r StructuredResult
	facts := chronological(ctx.Facts)

	alerts, findings, dets := len(ctx.FactsByType(FactAlert)), len(ctx.FactsByType(FactFinding)), len(ctx.FactsByType(FactDetection))
	assets, corr := len(ctx.FactsByType(FactAsset)), len(ctx.FactsByType(FactCorrelation))
	r.Summary = summaryLine(ctx.InvestigationID, alerts, dets, findings, assets, corr)

	for _, f := range facts {
		observeOrInfer(&r, f)
	}
	r.Unknown = baseUnknowns(ctx)
	r.EvidenceGaps = evidenceGaps(ctx)
	r.NextSteps = nextSteps(ctx)
	return r
}

func summaryLine(investigationID string, alerts, dets, findings, assets, corr int) string {
	scope := "This investigation"
	if investigationID == "" {
		scope = "This evidence set"
	}
	return scope + " includes " + pluralCount(alerts, "alert") + ", " + pluralCount(dets, "detection") + ", " +
		pluralCount(findings, "finding") + ", " + pluralCount(assets, "asset") + ", and " + pluralCount(corr, "correlation") +
		". The statements below are grounded in the cited evidence only."
}

func pluralCount(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// AnalyzeTimeline builds the deterministic chronological narrative
// phase13.md §24 specifies: chronological summary, significant events,
// gaps, and relationships — every claim cited.
func AnalyzeTimeline(ctx Context) StructuredResult {
	var r StructuredResult
	facts := chronological(ctx.Facts)
	if len(facts) == 0 {
		r.Summary = "No timeline evidence is available for this scope."
		r.Unknown = baseUnknowns(ctx)
		return r
	}
	r.Summary = "Chronological account of " + strconv.Itoa(len(facts)) + " evidence item(s), oldest first."
	for _, f := range facts {
		observeOrInfer(&r, f)
	}
	if gap, ok := largestGap(facts); ok {
		r.infer("The largest gap between consecutive evidence items is " + gap + " — this platform does not claim to know what, if anything, occurred during that interval.")
	}
	r.Unknown = baseUnknowns(ctx)
	return r
}

func largestGap(facts []Fact) (string, bool) {
	if len(facts) < 2 {
		return "", false
	}
	var maxGap = facts[1].Timestamp.Sub(facts[0].Timestamp)
	for i := 1; i < len(facts); i++ {
		if g := facts[i].Timestamp.Sub(facts[i-1].Timestamp); g > maxGap {
			maxGap = g
		}
	}
	if maxGap <= 0 {
		return "", false
	}
	return maxGap.String(), true
}

// IdentifyEvidenceGaps builds the deterministic structured evidence-gap
// analysis phase13.md §25 specifies, as a StructuredResult suitable for
// Assistant.Run.
func IdentifyEvidenceGaps(ctx Context) StructuredResult {
	var r StructuredResult
	r.EvidenceGaps = evidenceGaps(ctx)
	if len(r.EvidenceGaps) == 0 {
		r.Summary = "No evidence-category gaps were identified against this platform's standard coverage checklist."
	} else {
		r.Summary = "Evidence-gap analysis relative to this platform's standard coverage checklist. Absence is reported, never invented content for what is missing."
	}
	r.Unknown = baseUnknowns(ctx)
	return r
}

// GenerateInvestigationQuestionsResult wraps GenerateInvestigationQuestions
// as a StructuredResult, for use with Assistant.Run.
func GenerateInvestigationQuestionsResult(ctx Context) StructuredResult {
	var r StructuredResult
	r.Questions = GenerateInvestigationQuestions(ctx)
	r.Summary = "Evidence-gap-driven investigation questions — each tied to what the available evidence does or does not already show."
	return r
}

// GenerateInvestigationReport builds the fuller draft report phase13.md
// §46 specifies — summary, timeline, findings/detections/correlations/
// intelligence, evidence gaps, and recommendations — reusing
// SummarizeInvestigation's grounding and adding NextSteps/Questions.
// Every section is marked AI-generated by the caller (internal/service/
// ai), never silently presented as an analyst's own writing (phase13.md
// §46's "clearly mark AI-generated sections").
func GenerateInvestigationReport(ctx Context) StructuredResult {
	r := SummarizeInvestigation(ctx)
	r.Questions = GenerateInvestigationQuestions(ctx)
	return r
}
