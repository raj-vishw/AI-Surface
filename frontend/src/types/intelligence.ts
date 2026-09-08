import type { Severity } from "@/lib/severity";

/** Mirrors internal/domain/intelligence (record/vulnerability/risk). */
export type IndicatorType =
  | "domain"
  | "subdomain"
  | "ipv4"
  | "ipv6"
  | "url"
  | "hostname"
  | "certificate"
  | "technology"
  | "hash";

export type IntelConfidence = "unknown" | "low" | "medium" | "high";

export type SourceType =
  | "local"
  | "dns"
  | "certificate"
  | "vulnerability"
  | "reputation"
  | "threat_feed";

export interface IntelligenceRecord {
  id: string;
  targetId: string;
  indicatorType: IndicatorType;
  indicatorValue: string;
  providerId: string;
  providerVersion: string;
  sourceType: SourceType;
  confidence: IntelConfidence;
  malicious: boolean;
  suspicious: boolean;
  summary: string;
  observedAt: string;
  expiresAt: string | null;
  createdAt: string;
}

export type VulnerabilityMatchStatus = "probable" | "confirmed" | "dismissed";

export interface VulnerabilityRecord {
  id: string;
  cveId: string | null;
  technology: string;
  versionRange: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  cvssScore: number | null;
  summary: string;
  publishedAt: string | null;
}

export interface VulnerabilityMatch {
  id: string;
  targetId: string;
  assetId: string;
  vulnerabilityId: string;
  status: VulnerabilityMatchStatus;
  matchedAt: string;
}

/** Mirrors internal/domain/intelligence.RiskScore exactly. Corrected
 * after backend inspection during API wiring: the real field is
 * `severity` (the same 5-level scale as findings/alerts/investigations),
 * not an invented 4-level "criticality" — see
 * internal/domain/intelligence/risk.go's RiskScore struct. */
export interface RiskScore {
  id: string;
  targetId: string;
  entityType: "asset" | "finding" | "investigation";
  entityId: string;
  score: number; // 0-100, higher = riskier
  severity: Severity;
  confidence: string;
  modelVersion: string;
  factors: RiskFactor[];
  explanation: string;
  calculatedAt: string;
}

export interface RiskFactor {
  name: string;
  points: number;
  description: string;
}
