import type { Severity } from "@/lib/severity";

/** Mirrors internal/domain/finding.Finding exactly. */

export type FindingCategory =
  | "configuration"
  | "authentication"
  | "authorization"
  | "cryptography"
  | "information_disclosure"
  | "exposure"
  | "api"
  | "web"
  | "infrastructure"
  | "technology"
  | "certificate"
  | "security_headers";

export type FindingScope = "asset" | "endpoint" | "target";

export type FindingStatus =
  | "open"
  | "resolved"
  | "reopened"
  | "accepted_risk"
  | "false_positive";

export interface FindingReference {
  label: string;
  url: string;
}

export interface Finding {
  id: string;
  targetId: string;
  assetId: string;
  endpointId: string | null;
  scanId: string | null;

  detectorId: string;
  detectorVersion: number;
  title: string;
  description: string;

  category: FindingCategory;
  scope: FindingScope;

  severity: Severity;
  detectorSeverity: Severity;
  confidence: number;

  status: FindingStatus;

  remediation: string;
  references: FindingReference[];

  severityOverridden: boolean;
  severityOverrideReason: string;
  severityOverriddenAt: string | null;

  suppressionReason: string;

  firstSeen: string;
  lastSeen: string;
  resolvedAt: string | null;
  createdAt: string;
  updatedAt: string;

  /** Denormalized for table display — the underlying asset's display name. */
  assetName?: string;
}

/** Mirrors internal/domain/finding.Evidence (append-only, per-scan snapshot). */
export interface FindingEvidence {
  id: string;
  findingId: string;
  scanId: string;
  excerpt: string;
  observedAt: string;
  createdAt: string;
}

/** Mirrors internal/domain/finding.Event (lifecycle trail). */
export type FindingEventType =
  | "created"
  | "reobserved"
  | "severity_changed"
  | "severity_overridden"
  | "status_changed"
  | "resolved"
  | "reopened";

export interface FindingLifecycleEvent {
  id: string;
  findingId: string;
  eventType: FindingEventType;
  description: string;
  actor: string | null;
  occurredAt: string;
}
