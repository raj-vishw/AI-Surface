import type { Severity } from "@/lib/severity";

/** Mirrors internal/domain/rule (rule/match/alert/suppression). */

export type RuleStatus = "draft" | "enabled" | "disabled" | "deprecated";

export type RuleType = "threshold" | "sequence" | "aggregation" | "simple";

/** internal/domain/rule.Confidence is a string enum, not a 0-1 float
 * (unlike asset/finding Confidence) — corrected after backend
 * inspection during API wiring. */
export type RuleConfidence = "very_low" | "low" | "medium" | "high" | "very_high";

/** No `version` field: internal/domain/rule.Rule doesn't carry a
 * current-version number itself (tracked separately via rule.Version
 * rows) — corrected after backend inspection during API wiring. */
export interface Rule {
  id: string;
  targetId: string;
  name: string;
  description: string;
  status: RuleStatus;
  severity: Severity;
  confidence: RuleConfidence;
  ruleType: RuleType;
  category: string;
  tags: string[];
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

export type MatchStatus = "open" | "acknowledged" | "resolved" | "suppressed";

export interface DetectionMatch {
  id: string;
  targetId: string;
  ruleId: string;
  ruleVersion: number;
  ruleName?: string;
  status: MatchStatus;
  fingerprint: string;
  firstObservedAt: string;
  lastObservedAt: string;
  createdAt: string;
}

export type AlertStatus =
  | "open"
  | "acknowledged"
  | "investigating"
  | "resolved"
  | "suppressed";

export interface Alert {
  id: string;
  targetId: string;
  detectionMatchId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: RuleConfidence;
  status: AlertStatus;
  investigationId: string | null;
  ruleName?: string;
  firstObservedAt: string;
  lastObservedAt: string;
  createdAt: string;
  updatedAt: string;
}
