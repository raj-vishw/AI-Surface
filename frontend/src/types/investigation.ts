import type { Severity } from "@/lib/severity";

/** Mirrors internal/domain/investigation (investigation/timeline/evidence/
 * hypothesis/notes/relationship/cluster). */

export type InvestigationStatus =
  | "new"
  | "open"
  | "investigating"
  | "contained"
  | "resolved"
  | "closed";

export type Priority = "low" | "normal" | "high" | "urgent";

export type InvestigationConfidence =
  | "very_low"
  | "low"
  | "medium"
  | "high"
  | "very_high";

export interface Investigation {
  id: string;
  targetId: string;
  title: string;
  description: string;
  status: InvestigationStatus;
  priority: Priority;
  severity: Severity;
  confidence: InvestigationConfidence;
  createdBy: string;
  assignedTo: string;
  detectedAt: string | null;
  firstObservedAt: string | null;
  lastObservedAt: string | null;
  version: number;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
}

export type TimelineEventType =
  | "finding_added"
  | "evidence_attached"
  | "note_added"
  | "hypothesis_proposed"
  | "relationship_added"
  | "status_changed"
  | "ai_analysis"
  | "asset_change";

export interface TimelineEvent {
  id: string;
  targetId: string;
  investigationId: string;
  timestamp: string;
  type: TimelineEventType;
  sourceType: string;
  sourceId: string | null;
  title: string;
  description: string;
  severity: Severity | null;
  actor: string;
  createdAt: string;
}

export interface InvestigationEvidence {
  id: string;
  investigationId: string;
  sourceType: string;
  sourceId: string;
  description: string;
  attachedBy: string;
  attachedAt: string;
}

export type HypothesisStatus = "proposed" | "supported" | "refuted" | "confirmed";

export interface Hypothesis {
  id: string;
  investigationId: string;
  title: string;
  description: string;
  status: HypothesisStatus;
  confidence: InvestigationConfidence;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

export interface InvestigationNote {
  id: string;
  investigationId: string;
  authorId: string;
  content: string;
  aiGenerated: boolean;
  approvedBy: string | null;
  approvedAt: string | null;
  createdAt: string;
}

export type RelationshipType =
  | "same_asset"
  | "same_endpoint"
  | "temporal_proximity"
  | "shared_technology"
  | "shared_indicator";

export type RelationshipStatus = "candidate" | "confirmed";

export interface Relationship {
  id: string;
  investigationId: string;
  sourceType: string;
  sourceId: string;
  targetType: string;
  targetId: string;
  type: RelationshipType;
  status: RelationshipStatus;
  score: number;
}

export type ClusterStatus = "suggested" | "accepted" | "rejected";

export interface IncidentCluster {
  id: string;
  targetId: string;
  title: string;
  confidence: InvestigationConfidence;
  status: ClusterStatus;
  acceptedInvestigationId: string | null;
  memberCount: number;
  createdAt: string;
  updatedAt: string;
}
