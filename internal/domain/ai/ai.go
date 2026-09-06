// Package ai defines the platform's AI-assistant persistence model
// (phase13.md §6-9): the Session an analyst opens against one Target (and,
// usually, one Phase 9 Investigation), the Messages exchanged within it,
// and the Request/Response/ToolCall audit trail every AI operation leaves
// behind. It mirrors internal/domain/correlation and internal/domain/rule's
// shape and independence discipline — no dependency on any other domain
// package; every cross-entity reference is a bare uuid.UUID plus a string
// type tag, not an imported type.
//
// This package holds only the *persisted* representation. The engine that
// actually builds context, calls a provider, and validates output —
// citation checking, redaction, guardrails, structured-result assembly —
// lives in internal/ai and has no dependency on this package (the same
// engine/domain split internal/correlation keeps from internal/domain/
// correlation, and internal/ruleengine keeps from internal/domain/rule).
// internal/service/ai is the bridge.
//
// Scope adaptations, documented once here rather than at every call site
// (phase13.md's own instruction to inspect and adapt to this platform's
// real architecture, exactly as Phase 11/12 already did):
//
//   - No auth/RBAC exists anywhere in this codebase. UserID here is a
//     plain analyst-supplied identifier — the same convention
//     investigation.Investigation.CreatedBy, rule.Suppression.RemovedBy,
//     and correlation.Correlation.ConfirmedBy already use. "Authorization"
//     in this package means TargetID scoping, not per-resource ACLs.
//   - "ProjectID" in phase13.md is this platform's existing TargetID —
//     the same mapping every prior phase's report already established.
//   - No job/worker queue exists yet (see cmd/worker's own doc comment,
//     unchanged since Phase 1). AI requests — including report drafting —
//     run synchronously from the CLI, bounded by a request timeout and
//     cancelable via context, never a fabricated queued/running/completed
//     job-status table (phase13.md §109/§110, adapted as a documented
//     Known Limitation exactly like Phase 12 adapted the same absence for
//     its own "worker pool").
//   - No REST API exists anywhere in this codebase (only /health,
//     /ready — see internal/httpserver). phase13.md §77-82's endpoints are
//     adapted to `ai-recon ai ...` CLI subcommands, the same adaptation
//     Phase 9-12 already applied to their own API sections.
package ai

import (
	"strings"

	"github.com/google/uuid"
)

// TaskType names one kind of AI operation (phase13.md §6). A closed,
// deliberately small set — never an arbitrary free-form string, so every
// task has a single well-known prompt version and output shape.
type TaskType string

// Recognized task types.
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

var validTaskTypes = map[TaskType]bool{
	TaskInvestigationSummary: true, TaskAlertExplanation: true, TaskDetectionExplanation: true,
	TaskCorrelationAnalysis: true, TaskAttackChainAnalysis: true, TaskTimelineSummary: true,
	TaskIntelligenceSummary: true, TaskEvidenceGapAnalysis: true, TaskInvestigationQuestions: true,
	TaskReportDraft: true, TaskChatReply: true,
}

// Valid reports whether t is a recognized task type.
func (t TaskType) Valid() bool { return validTaskTypes[t] }

// Role identifies who authored one Message (phase13.md §9). The "system"
// role is recorded for audit purposes only — it is never rendered back to
// an analyst as part of a chat transcript (phase13.md §9: "do not expose
// hidden system instructions to users").
type Role string

// Recognized message roles.
const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleSystem    Role = "system"
)

var validRoles = map[Role]bool{RoleUser: true, RoleAssistant: true, RoleSystem: true}

// Valid reports whether r is a recognized role.
func (r Role) Valid() bool { return validRoles[r] }

// Confidence is the AI assistant's confidence in its own generated
// interpretation (phase13.md §40/§41) — deliberately never conflated with
// internal/domain/correlation.Confidence, internal/domain/rule.Confidence,
// or a risk score. See internal/ai.Confidence's doc comment for the full
// "confidence in interpretation, not probability of attack" rule this
// mirrors.
type Confidence string

// Recognized confidence levels — the same three-level scale
// internal/domain/correlation.Confidence uses, independently declared.
const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

var validConfidences = map[Confidence]bool{ConfidenceLow: true, ConfidenceMedium: true, ConfidenceHigh: true}

// Valid reports whether c is a recognized confidence level.
func (c Confidence) Valid() bool { return validConfidences[c] }

// ToolResultStatus records whether one AI tool invocation succeeded
// (phase13.md §34).
type ToolResultStatus string

// Recognized tool result statuses.
const (
	ToolResultSuccess ToolResultStatus = "success"
	ToolResultError   ToolResultStatus = "error"
	ToolResultDenied  ToolResultStatus = "denied"
)

var validToolResultStatuses = map[ToolResultStatus]bool{
	ToolResultSuccess: true, ToolResultError: true, ToolResultDenied: true,
}

// Valid reports whether s is a recognized tool result status.
func (s ToolResultStatus) Valid() bool { return validToolResultStatuses[s] }

// trimmedNotEmpty is a small validation helper shared by every Validate
// method below — mirrors the identical inline check every other domain
// package repeats.
func trimmedNotEmpty(s string) bool { return strings.TrimSpace(s) != "" }

// nilOrValidUUID reports whether id is either uuid.Nil (meaning "not set")
// or a syntactically valid, non-nil UUID — used for optional
// cross-references like Session.InvestigationID.
func nilOrValidUUID(id *uuid.UUID) bool { return id == nil || *id != uuid.Nil }
