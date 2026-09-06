// Package ai implements Phase 13's evidence-grounded investigation
// assistant: a provider-agnostic engine that assembles bounded, redacted
// context from this platform's own already-persisted evidence, builds a
// versioned prompt, calls a pluggable AIProvider, and validates the result
// before it is ever shown to an analyst (phase13.md §2-3).
//
// Like internal/correlation and internal/ruleengine before it, this
// package is entirely self-contained: it has no dependency on
// internal/domain/ai, internal/repository, or database/pgx of any kind.
// It knows only its own vocabulary (TaskType, Fact, Confidence, ...),
// deliberately independent of internal/domain/ai's persisted shapes —
// internal/service/ai is the bridge that assembles a Context from real
// repositories and persists a Result through internal/repository/ai,
// exactly the "engine is self-contained, the service layer bridges it"
// split every prior phase's own engine package follows.
//
// # The analyst assistant, not an autonomous operator
//
// Every function in this package produces advisory output for a human
// analyst to review (phase13.md §7). Nothing here ever:
//
//   - changes an alert's severity, an investigation's status, a
//     correlation's confirmation state, or a risk score (phase13.md §90);
//   - infers threat-actor identity, nationality, organization, or motive
//     (phase13.md §18);
//   - executes a tool that writes, blocks, scans, or exploits anything —
//     every registered Tool in this package and internal/ai/tools is
//     read-only (phase13.md §31);
//   - treats a citation as valid unless it was actually present in the
//     Context handed to it (phase13.md §14/§15/§42).
package ai

// TaskType names one kind of AI operation — an independent copy of
// internal/domain/ai.TaskType's vocabulary (see that package's doc comment
// for why this engine never imports it).
type TaskType string

// Recognized task types (phase13.md §6).
const (
	TaskInvestigationSummary   TaskType = "investigation_summary"
	TaskAlertExplanation       TaskType = "alert_explanation"
	TaskDetectionExplanation   TaskType = "detection_explanation"
	TaskCorrelationAnalysis    TaskType = "correlation_analysis"
	TaskAttackChainAnalysis    TaskType = "attack_chain_analysis"
	TaskTimelineSummary        TaskType = "timeline_summary"
	TaskIntelligenceSummary    TaskType = "intelligence_summary"
	TaskEvidenceGapAnalysis    TaskType = "evidence_gap_analysis"
	TaskInvestigationQuestions TaskType = "investigation_questions"
	TaskReportDraft            TaskType = "report_draft"
	TaskChatReply              TaskType = "chat_reply"
)

// PromptVersion returns the current versioned prompt identifier for t
// (phase13.md §97), e.g. "investigation_summary:v1". Every task has
// exactly one current version; a future revision bumps the suffix rather
// than silently changing v1's behavior, so a stored Request.PromptVersion
// always identifies exactly which template produced it.
func (t TaskType) PromptVersion() string {
	return string(t) + ":v1"
}

// Confidence is the AI assistant's confidence in its own generated
// interpretation — never a probability that an attack occurred, and never
// conflated with any detection/correlation/risk confidence value computed
// elsewhere in this platform (phase13.md §40/§41). Deliberately the same
// three-level scale internal/correlation.Confidence already uses, kept as
// an independent copy for identical reasons.
type Confidence string

// Recognized confidence levels.
const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)
