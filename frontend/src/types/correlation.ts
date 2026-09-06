import type { Severity } from "@/lib/severity";

/** Mirrors internal/domain/correlation (correlation/node/edge/chain/stage). */

export type CorrelationStatus = "candidate" | "confirmed" | "dismissed" | "merged";
export type EdgeConfidence = "low" | "medium" | "high";

export interface Correlation {
  id: string;
  targetId: string;
  title: string;
  description: string;
  status: CorrelationStatus;
  severity: Severity;
  confidence: EdgeConfidence;
  /** 0-100 evidence-strength score (never a probability of attack). */
  score: number;
  strategy?: string;
  createdAt: string;
  updatedAt: string;
}

export type NodeType =
  | "finding"
  | "detection_match"
  | "alert"
  | "asset"
  | "endpoint"
  | "intelligence_record"
  | "investigation";

export type EvidenceRole = "trigger" | "supporting";

export interface CorrelationNode {
  id: string;
  correlationId: string;
  type: NodeType;
  referenceId: string;
  role: EvidenceRole;
  /** Denormalized label for graph display, e.g. a finding's title. */
  label: string;
}

export type EdgeRelationship =
  | "temporal_proximity"
  | "same_asset"
  | "shared_technology"
  | "shared_indicator"
  | "escalation";

export interface CorrelationEdge {
  id: string;
  correlationId: string;
  sourceNodeId: string;
  targetNodeId: string;
  relationship: EdgeRelationship;
  confidence: EdgeConfidence;
}

export type ChainStatus = "candidate" | "confirmed" | "dismissed";

export interface AttackChain {
  id: string;
  correlationId: string;
  name: string;
  description: string;
  confidence: EdgeConfidence;
  severity: Severity;
  status: ChainStatus;
  createdAt: string;
  updatedAt: string;
}

export type StageType =
  | "initial_activity"
  | "authentication"
  | "execution"
  | "privilege_change"
  | "persistence_signal"
  | "discovery_signal"
  | "network_activity"
  | "data_access"
  | "impact_signal";

export const STAGE_LABELS: Record<StageType, string> = {
  initial_activity: "Initial Activity",
  authentication: "Authentication",
  execution: "Execution",
  privilege_change: "Privilege Change",
  persistence_signal: "Persistence Signal",
  discovery_signal: "Discovery Signal",
  network_activity: "Network Activity",
  data_access: "Data Access",
  impact_signal: "Impact Signal",
};

export interface StageEvidenceRef {
  type: NodeType;
  id: string;
}

export interface AttackChainStage {
  id: string;
  attackChainId: string;
  stage: StageType;
  order: number;
  confidence: EdgeConfidence;
  evidence: StageEvidenceRef[];
}
