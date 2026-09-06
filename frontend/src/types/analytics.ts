/** Mirrors internal/analytics (Phase 14: overview/risk/alerts/detections/
 * findings/assets/correlations/investigations/intelligence/AI/posture). */

export interface TimeRange {
  start: string;
  end: string;
  interval: "hour" | "day" | "week";
}

export type RangePreset = "24h" | "7d" | "30d" | "90d";

export interface Bucket {
  bucketStart: string;
  count: number;
}

export interface NamedCount {
  name: string;
  count: number;
}

export interface Overview {
  totalAssets: number;
  monitoredAssets: number;
  openFindings: number;
  openAlerts: number;
  activeInvestigations: number;
  criticalRiskAssets: number;
  highRiskAssets: number;
  openCorrelations: number;
  intelligenceRecords: number;
}

export interface RiskBucket {
  bucketStart: string;
  averageScore: number;
  maxScore: number;
  criticalCount: number;
  highCount: number;
}

export interface RiskAnalytics {
  trend: RiskBucket[];
  distribution: NamedCount[];
}

export interface AlertAnalytics {
  overTime: Bucket[];
  bySeverity: NamedCount[];
  byStatus: NamedCount[];
  byRule: NamedCount[];
}

export interface RuleRate {
  rule: string;
  matches: number;
  alerts: number;
  dismissed: number;
  alertConversion: number;
  dismissalRate: number;
}

export interface DetectionAnalytics {
  matchesOverTime: Bucket[];
  byRule: NamedCount[];
  bySeverity: NamedCount[];
  enabledRules: number;
  disabledRules: number;
  noisyRules: RuleRate[];
}

export interface FindingAnalytics {
  bySeverity: NamedCount[];
  byCategory: NamedCount[];
  overTime: Bucket[];
  open: number;
  resolved: number;
  affectedAssets: NamedCount[];
}

export interface AssetAnalytics {
  total: number;
  byType: NamedCount[];
  byStatus: NamedCount[];
  riskCritical: number;
  riskHigh: number;
}

export interface AttackSurfaceTrend {
  newAssets: Bucket[];
  removedAssets: Bucket[];
  byType: NamedCount[];
}

export interface CorrelationAnalytics {
  overTime: Bucket[];
  bySeverity: NamedCount[];
  byConfidence: NamedCount[];
  byStatus: NamedCount[];
  byStrategy: NamedCount[];
}

export interface AttackChainAnalytics {
  overTime: Bucket[];
  bySeverity: NamedCount[];
  byConfidence: NamedCount[];
  commonStages: NamedCount[];
}

export interface InvestigationAnalytics {
  openedOverTime: Bucket[];
  closedOverTime: Bucket[];
  bySeverity: NamedCount[];
  byStatus: NamedCount[];
  active: number;
  meanDurationSeconds: number;
  closedCount: number;
}

export interface IntelligenceAnalytics {
  total: number;
  byIndicatorType: NamedCount[];
  byProvider: NamedCount[];
  byConfidence: NamedCount[];
  expired: number;
}

export interface AIAnalytics {
  requestsOverTime: Bucket[];
  byTaskType: NamedCount[];
  byProvider: NamedCount[];
  averageLatencyMs: number;
  inputTokens: number;
  outputTokens: number;
  failures: number;
  toolCallsByTool: NamedCount[];
}

/** Security posture = 100 - average(latest risk score per scored entity)
 * — a documented derivation, never an independently invented score. */
export interface SecurityPosture {
  score: number;
  scoredEntities: number;
  criticalCount: number;
  highCount: number;
}
