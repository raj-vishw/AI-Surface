import type { Severity } from "@/lib/severity";

/** Mirrors internal/domain/rule (rule/match/alert/suppression). */

export type RuleStatus = "draft" | "enabled" | "disabled" | "deprecated";

export type RuleType = "threshold" | "sequence" | "aggregation" | "simple";

export interface Rule {
  id: string;
  targetId: string;
  name: string;
  description: string;
  version: number;
  status: RuleStatus;
  severity: Severity;
  confidence: number;
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
  confidence: number;
  status: AlertStatus;
  investigationId: string | null;
  ruleName?: string;
  firstObservedAt: string;
  lastObservedAt: string;
  createdAt: string;
  updatedAt: string;
}
