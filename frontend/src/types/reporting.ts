/** Mirrors internal/domain/reporting (Phase 14: report/evidence/control). */

export type ReportType =
  | "investigation"
  | "asset"
  | "correlation"
  | "attack_surface"
  | "detection"
  | "executive"
  | "audit";

export type ReportStatus = "draft" | "generated" | "reviewed" | "approved";

export interface Report {
  id: string;
  targetId: string;
  reportType: ReportType;
  subjectId: string | null;
  version: number;
  title: string;
  status: ReportStatus;
  contentHash: string;
  generatedBy: string;
  approvedBy: string | null;
  approvedAt: string | null;
  approvalNotes: string;
  createdAt: string;
  generatedAt: string;
}

export interface ReportSection {
  title: string;
  body: string;
  citations: string[];
}

export type EvidenceItemType =
  | "finding"
  | "alert"
  | "detection_match"
  | "correlation"
  | "investigation"
  | "intelligence_record"
  | "asset"
  | "event";

export interface EvidencePackage {
  id: string;
  targetId: string;
  reportId: string;
  itemCount: number;
  manifestHash: string;
  createdBy: string;
  createdAt: string;
}

export interface EvidenceItem {
  id: string;
  packageId: string;
  itemType: EvidenceItemType;
  referenceId: string;
  hash: string;
  timestamp: string;
}

export interface ControlEvidence {
  id: string;
  targetId: string;
  controlId: string;
  evidenceType: EvidenceItemType;
  referenceId: string;
  description: string;
  collectedAt: string;
}

export interface ControlFreshness {
  controlId: string;
  evidenceCount: number;
  mostRecentAt: string;
}
