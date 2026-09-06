/** Mirrors internal/domain/ai + internal/ai's StructuredResult/Fact —
 * the AI Trust UI (spec §31) is built directly on StructuredResult's
 * real shape: Observed = Evidence, Inferred = AI Analysis, Unknown +
 * EvidenceGaps = Uncertainty, NextSteps = Recommendation. Nothing here
 * is a UI invention layered on top of free-form text. */

export type AIRole = "user" | "assistant" | "system";

export interface AISession {
  id: string;
  targetId: string;
  investigationId: string | null;
  userId: string;
  createdAt: string;
  updatedAt: string;
}

export interface AIMessage {
  id: string;
  sessionId: string;
  role: AIRole;
  content: string;
  createdAt: string;
}

export type ToolResultStatus = "success" | "error" | "empty";

export interface AIToolCall {
  id: string;
  sessionId: string | null;
  requestId: string | null;
  targetId: string;
  tool: string;
  arguments: Record<string, unknown>;
  resultStatus: ToolResultStatus;
  resultSummary: string;
  createdAt: string;
}

export type AITaskType =
  | "investigation_summary"
  | "finding_explanation"
  | "correlation_analysis"
  | "next_steps"
  | "chat";

export type AIConfidence = "low" | "medium" | "high";

/** internal/ai.StructuredResult — the deterministic, citation-grounded
 * structure every AI response is built from, regardless of provider. */
export interface AIStructuredResult {
  summary: string;
  observed: string[];
  inferred: string[];
  unknown: string[];
  evidenceGaps: string[];
  nextSteps: string[];
  questions: string[];
  citations: string[];
}

export interface AIResult {
  id: string;
  sessionId: string | null;
  taskType: AITaskType;
  content: string;
  structured: AIStructuredResult;
  provider: string;
  model: string;
  confidence: AIConfidence;
  citations: string[];
  fabricatedCitationsRemoved: string[];
  unsupportedClaimsRewritten: number;
  attributionRejected: boolean;
  truncated: boolean;
  inputTokens: number;
  outputTokens: number;
  latencyMs: number;
  createdAt: string;
}

/** A citation token like "[alert:3fae21a0-...]" — parsed for linking
 * directly to the underlying evidence (spec §31). */
export interface ParsedCitation {
  token: string;
  entityType: string;
  entityId: string;
}

export function parseCitation(token: string): ParsedCitation | null {
  const match = /^\[([a-z_]+):([^\]]+)\]$/.exec(token);
  if (!match) return null;
  return { token, entityType: match[1], entityId: match[2] };
}
