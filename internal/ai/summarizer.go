package ai

// ExplainAlert builds the deterministic structured explanation
// phase13.md §20 specifies: what triggered the alert, the rule/evidence
// involved, why it matched, severity/confidence, related activity, and
// limitations — grounded entirely in the alert/detection/finding/asset
// facts supplied. Never changes the alert's own severity (phase13.md §20:
// "do not change alert severity automatically" — this function has no
// way to, by construction: it only reads Context).
func ExplainAlert(ctx Context) StructuredResult {
	var r StructuredResult
	alerts := ctx.FactsByType(FactAlert)
	if len(alerts) == 0 {
		r.Summary = "No alert evidence is available for this scope."
		r.Unknown = baseUnknowns(ctx)
		return r
	}
	r.Summary = "Explanation of " + pluralCount(len(alerts), "alert") + ", grounded in the evidence cited below."
	for _, f := range chronological(ctx.Facts) {
		observeOrInfer(&r, f)
	}
	if !hasAny(ctx, FactDetection) {
		r.EvidenceGaps = append(r.EvidenceGaps, "The underlying detection match for this alert was not included in this context.")
	}
	if !hasAny(ctx, FactAsset) {
		r.EvidenceGaps = append(r.EvidenceGaps, "No asset context is available to establish exposure or criticality.")
	}
	r.Unknown = append(baseUnknowns(ctx), "Whether this alert represents a false positive — that determination is an analyst decision, not an automated one.")
	r.NextSteps = nextSteps(ctx)
	return r
}

// ExplainDetection builds the deterministic structured explanation
// phase13.md §21 specifies: rule, rule version, matched conditions/events,
// evidence, and false-positive considerations.
func ExplainDetection(ctx Context) StructuredResult {
	var r StructuredResult
	dets := ctx.FactsByType(FactDetection)
	if len(dets) == 0 {
		r.Summary = "No detection-match evidence is available for this scope."
		r.Unknown = baseUnknowns(ctx)
		return r
	}
	r.Summary = "Explanation of the detection match(es) below, including the rule that produced them."
	for _, f := range chronological(ctx.Facts) {
		observeOrInfer(&r, f)
	}
	r.Unknown = append(baseUnknowns(ctx),
		"Whether the matched pattern reflects a genuine security issue rather than benign activity that happens to match the rule's conditions.")
	r.EvidenceGaps = evidenceGaps(ctx)
	r.NextSteps = nextSteps(ctx)
	return r
}

// AnalyzeCorrelation builds the deterministic structured analysis
// phase13.md §22 specifies: why evidence was correlated, shared entities,
// temporal/detection relationships, intelligence context, confidence, and
// limitations — reading directly from the correlation/edge/node facts a
// Phase 12 correlation's own graph supplies.
func AnalyzeCorrelation(ctx Context) StructuredResult {
	var r StructuredResult
	corr := ctx.FactsByType(FactCorrelation)
	if len(corr) == 0 {
		r.Summary = "No correlation evidence is available for this scope."
		r.Unknown = baseUnknowns(ctx)
		return r
	}
	r.Summary = "Analysis of a correlation grouping " + pluralCount(len(ctx.Facts)-len(corr), "related evidence item") + "."
	for _, f := range chronological(ctx.Facts) {
		observeOrInfer(&r, f)
	}
	r.Unknown = append(baseUnknowns(ctx),
		"Whether the correlated items share a common cause, as opposed to coincidental proximity in time or shared infrastructure.")
	r.NextSteps = nextSteps(ctx)
	return r
}

// AnalyzeAttackChain builds the deterministic structured analysis
// phase13.md §23 specifies: per-stage evidence/confidence/observed-or-
// inferred status, plus confirmed observations, inferred relationships,
// missing stages, and uncertain areas. It never invents a missing stage
// (phase13.md §23) — a gap is reported as an absence, exactly the
// discipline internal/correlation's own chain.go already documents.
func AnalyzeAttackChain(ctx Context) StructuredResult {
	var r StructuredResult
	stages := ctx.FactsByType(FactAttackStage)
	if len(stages) == 0 {
		r.Summary = "No attack chain has been generated for this correlation — there is insufficient classifiable evidence for a staged narrative."
		r.Unknown = baseUnknowns(ctx)
		return r
	}
	r.Summary = "Staged account of " + pluralCount(len(stages), "attack-chain stage") + ", in order. Stages absent from this list are gaps, not confirmed non-events."
	for _, f := range chronological(ctx.Facts) {
		observeOrInfer(&r, f)
	}
	r.infer("This platform classifies evidence into stages using rule/category keyword heuristics — it does not map onto a formal kill-chain or MITRE ATT&CK technique.")
	r.Unknown = baseUnknowns(ctx)
	r.NextSteps = nextSteps(ctx)
	return r
}

// SummarizeIntelligence builds the deterministic structured summary of
// threat-intelligence context (phase13.md's general "summarize threat
// intelligence" requirement) — every verdict is presented as a
// third-party classification, never this platform's own observed
// activity, mirroring internal/correlation/strategies' own intelligence
// strategy discipline.
func SummarizeIntelligence(ctx Context) StructuredResult {
	var r StructuredResult
	intel := ctx.FactsByType(FactIntelligence)
	if len(intel) == 0 {
		r.Summary = "No threat-intelligence evidence is available for this scope."
		r.Unknown = baseUnknowns(ctx)
		return r
	}
	r.Summary = "Summary of " + pluralCount(len(intel), "threat-intelligence record") + " (third-party classifications, not this platform's own observations)."
	for _, f := range intel {
		r.observe("Intelligence: "+f.Summary, f.Citation())
	}
	r.Unknown = append(baseUnknowns(ctx), "Whether any provider's verdict reflects a current, still-valid classification.")
	return r
}
