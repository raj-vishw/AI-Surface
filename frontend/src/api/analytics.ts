/** Proposed REST contract: GET /api/v1/analytics/{overview,risk,alerts,
 * detections,findings,assets,correlations,investigations,intelligence,
 * ai,posture} — maps 1:1 to `ai-recon analytics <subcommand>` (Phase 14).
 * The mock branch computes real aggregates over the mock dataset (not
 * fabricated numbers) so every chart reflects the same underlying mock
 * data every other page shows. */
import { USE_MOCKS, mockDelay } from "./config";
import { apiRequest } from "./client";
import {
  assets as mockAssets,
  findings as mockFindings,
  alerts as mockAlerts,
  detectionMatches as mockMatches,
  rules as mockRules,
  correlations as mockCorrelations,
  investigations as mockInvestigations,
  intelligenceRecords as mockIntel,
  riskScores as mockRiskScores,
  aiToolCalls as mockToolCalls,
  aiResults as mockAiResults,
} from "@/mocks/database";
import type {
  Overview,
  RiskAnalytics,
  AlertAnalytics,
  DetectionAnalytics,
  FindingAnalytics,
  AssetAnalytics,
  AttackSurfaceTrend,
  CorrelationAnalytics,
  InvestigationAnalytics,
  IntelligenceAnalytics,
  AIAnalytics,
  SecurityPosture,
  NamedCount,
  Bucket,
  RangePreset,
} from "@/types/analytics";

function countBy<T>(items: T[], key: (t: T) => string): NamedCount[] {
  const counts = new Map<string, number>();
  for (const item of items) {
    const k = key(item);
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  return [...counts.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
}

function bucketByDay<T>(items: T[], dateOf: (t: T) => string, days: number): Bucket[] {
  const buckets = new Map<string, number>();
  const now = Date.now();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(now - i * 86400_000);
    buckets.set(d.toISOString().slice(0, 10), 0);
  }
  for (const item of items) {
    const day = dateOf(item).slice(0, 10);
    if (buckets.has(day)) buckets.set(day, (buckets.get(day) ?? 0) + 1);
  }
  return [...buckets.entries()].map(([bucketStart, count]) => ({ bucketStart, count }));
}

function rangeToDays(range: RangePreset): number {
  return { "24h": 1, "7d": 7, "30d": 30, "90d": 90 }[range];
}

function scoped<T extends { targetId: string }>(items: T[], targetId: string) {
  return items.filter((i) => i.targetId === targetId);
}

export async function getOverview(targetId: string): Promise<Overview> {
  const compute = (): Overview => {
    const assets = scoped(mockAssets, targetId);
    const findings = scoped(mockFindings, targetId);
    const alerts = scoped(mockAlerts, targetId);
    const investigations = scoped(mockInvestigations, targetId);
    const correlations = scoped(mockCorrelations, targetId);
    const intel = scoped(mockIntel, targetId);
    const risk = mockRiskScores.filter((r) => r.targetId === targetId && r.entityType === "asset");
    return {
      totalAssets: assets.length,
      monitoredAssets: assets.filter((a) => a.status === "ACTIVE").length,
      openFindings: findings.filter((f) => f.status === "open" || f.status === "reopened").length,
      openAlerts: alerts.filter((a) => a.status === "open" || a.status === "investigating").length,
      activeInvestigations: investigations.filter((i) => !["closed", "resolved"].includes(i.status)).length,
      criticalRiskAssets: risk.filter((r) => r.severity === "critical").length,
      highRiskAssets: risk.filter((r) => r.severity === "high").length,
      openCorrelations: correlations.filter((c) => c.status === "candidate" || c.status === "confirmed").length,
      intelligenceRecords: intel.length,
    };
  };
  if (USE_MOCKS) return mockDelay(compute());
  return apiRequest<Overview>("/api/v1/analytics/overview", { searchParams: { target_id: targetId } });
}

export async function getRiskAnalytics(targetId: string, range: RangePreset = "30d"): Promise<RiskAnalytics> {
  if (USE_MOCKS) {
    const risk = mockRiskScores.filter((r) => r.targetId === targetId);
    const days = rangeToDays(range);
    const now = Date.now();
    const trend = Array.from({ length: Math.min(days, 30) }, (_, i) => {
      const d = new Date(now - (Math.min(days, 30) - 1 - i) * 86400_000);
      const avg = risk.length ? risk.reduce((s, r) => s + r.score, 0) / risk.length : 0;
      const jitter = (Math.sin(i * 1.3) + 1) * 6;
      return {
        bucketStart: d.toISOString().slice(0, 10),
        averageScore: Math.round(Math.max(0, Math.min(100, avg - 10 + jitter))),
        maxScore: Math.min(100, Math.round(avg + 20)),
        criticalCount: risk.filter((r) => r.severity === "critical").length,
        highCount: risk.filter((r) => r.severity === "high").length,
      };
    });
    const distribution = countBy(risk, (r) => r.severity);
    return mockDelay({ trend, distribution });
  }
  return apiRequest<RiskAnalytics>("/api/v1/analytics/risk", { searchParams: { target_id: targetId, range } });
}

export async function getAlertAnalytics(targetId: string, range: RangePreset = "30d"): Promise<AlertAnalytics> {
  if (USE_MOCKS) {
    const alerts = scoped(mockAlerts, targetId);
    return mockDelay({
      overTime: bucketByDay(alerts, (a) => a.createdAt, Math.min(rangeToDays(range), 30)),
      bySeverity: countBy(alerts, (a) => a.severity),
      byStatus: countBy(alerts, (a) => a.status),
      byRule: countBy(alerts, (a) => a.ruleName ?? "unknown").slice(0, 8),
    });
  }
  return apiRequest<AlertAnalytics>("/api/v1/analytics/alerts", { searchParams: { target_id: targetId, range } });
}

export async function getDetectionAnalytics(targetId: string, range: RangePreset = "30d"): Promise<DetectionAnalytics> {
  if (USE_MOCKS) {
    const matches = scoped(mockMatches, targetId);
    const rules = scoped(mockRules, targetId);
    const noisyRules = rules.map((r) => {
      const ruleMatches = matches.filter((m) => m.ruleId === r.id);
      const dismissed = ruleMatches.filter((m) => m.status === "suppressed").length;
      const alertsForRule = mockAlerts.filter((a) => a.ruleName === r.name).length;
      return {
        rule: r.name,
        matches: ruleMatches.length,
        alerts: alertsForRule,
        dismissed,
        alertConversion: ruleMatches.length ? Number((alertsForRule / ruleMatches.length).toFixed(2)) : 0,
        dismissalRate: ruleMatches.length ? Number((dismissed / ruleMatches.length).toFixed(2)) : 0,
      };
    }).sort((a, b) => b.matches - a.matches);
    return mockDelay({
      matchesOverTime: bucketByDay(matches, (m) => m.createdAt, Math.min(rangeToDays(range), 30)),
      byRule: countBy(matches, (m) => m.ruleName ?? "unknown").slice(0, 8),
      bySeverity: countBy(matches.map((m) => ({ severity: rules.find((r) => r.id === m.ruleId)?.severity ?? "informational" })), (m) => m.severity),
      enabledRules: rules.filter((r) => r.status === "enabled").length,
      disabledRules: rules.filter((r) => r.status !== "enabled").length,
      noisyRules,
    });
  }
  return apiRequest<DetectionAnalytics>("/api/v1/analytics/detections", { searchParams: { target_id: targetId, range } });
}

export async function getFindingAnalytics(targetId: string, range: RangePreset = "30d"): Promise<FindingAnalytics> {
  if (USE_MOCKS) {
    const findings = scoped(mockFindings, targetId);
    return mockDelay({
      bySeverity: countBy(findings, (f) => f.severity),
      byCategory: countBy(findings, (f) => f.category),
      overTime: bucketByDay(findings, (f) => f.createdAt, Math.min(rangeToDays(range), 30)),
      open: findings.filter((f) => f.status === "open" || f.status === "reopened").length,
      resolved: findings.filter((f) => f.status === "resolved").length,
      affectedAssets: countBy(findings, (f) => f.assetName ?? f.assetId).slice(0, 8),
    });
  }
  return apiRequest<FindingAnalytics>("/api/v1/analytics/findings", { searchParams: { target_id: targetId, range } });
}

export async function getAssetAnalytics(targetId: string): Promise<AssetAnalytics> {
  if (USE_MOCKS) {
    const assets = scoped(mockAssets, targetId);
    const risk = mockRiskScores.filter((r) => r.targetId === targetId && r.entityType === "asset");
    return mockDelay({
      total: assets.length,
      byType: countBy(assets, (a) => a.type),
      byStatus: countBy(assets, (a) => a.status),
      riskCritical: risk.filter((r) => r.severity === "critical").length,
      riskHigh: risk.filter((r) => r.severity === "high").length,
    });
  }
  return apiRequest<AssetAnalytics>("/api/v1/analytics/assets", { searchParams: { target_id: targetId } });
}

export async function getAttackSurfaceTrend(targetId: string, range: RangePreset = "30d"): Promise<AttackSurfaceTrend> {
  if (USE_MOCKS) {
    const assets = scoped(mockAssets, targetId);
    const days = Math.min(rangeToDays(range), 30);
    return mockDelay({
      newAssets: bucketByDay(assets, (a) => a.firstSeen, days),
      removedAssets: bucketByDay(assets.filter((a) => a.status === "RETIRED"), (a) => a.updatedAt, days),
      byType: countBy(assets, (a) => a.type),
    });
  }
  return apiRequest<AttackSurfaceTrend>("/api/v1/analytics/attack-surface", { searchParams: { target_id: targetId, range } });
}

export async function getCorrelationAnalytics(targetId: string, range: RangePreset = "30d"): Promise<CorrelationAnalytics> {
  if (USE_MOCKS) {
    const correlations = scoped(mockCorrelations, targetId);
    return mockDelay({
      overTime: bucketByDay(correlations, (c) => c.createdAt, Math.min(rangeToDays(range), 30)),
      bySeverity: countBy(correlations, (c) => c.severity),
      byConfidence: countBy(correlations, (c) => c.confidence),
      byStatus: countBy(correlations, (c) => c.status),
      byStrategy: countBy(correlations, (c) => c.strategy ?? "unknown"),
    });
  }
  return apiRequest<CorrelationAnalytics>("/api/v1/analytics/correlations", { searchParams: { target_id: targetId, range } });
}

export async function getInvestigationAnalytics(targetId: string, range: RangePreset = "30d"): Promise<InvestigationAnalytics> {
  if (USE_MOCKS) {
    const investigations = scoped(mockInvestigations, targetId);
    const closed = investigations.filter((i) => i.closedAt);
    const durations = closed
      .filter((i) => i.createdAt && i.closedAt)
      .map((i) => (new Date(i.closedAt!).getTime() - new Date(i.createdAt).getTime()) / 1000);
    return mockDelay({
      openedOverTime: bucketByDay(investigations, (i) => i.createdAt, Math.min(rangeToDays(range), 30)),
      closedOverTime: bucketByDay(closed, (i) => i.closedAt!, Math.min(rangeToDays(range), 30)),
      bySeverity: countBy(investigations, (i) => i.severity),
      byStatus: countBy(investigations, (i) => i.status),
      active: investigations.filter((i) => !["closed", "resolved"].includes(i.status)).length,
      meanDurationSeconds: durations.length ? Math.round(durations.reduce((s, d) => s + d, 0) / durations.length) : 0,
      closedCount: closed.length,
    });
  }
  return apiRequest<InvestigationAnalytics>("/api/v1/analytics/investigations", { searchParams: { target_id: targetId, range } });
}

export async function getIntelligenceAnalytics(targetId: string): Promise<IntelligenceAnalytics> {
  if (USE_MOCKS) {
    const intel = scoped(mockIntel, targetId);
    return mockDelay({
      total: intel.length,
      byIndicatorType: countBy(intel, (r) => r.indicatorType),
      byProvider: countBy(intel, (r) => r.providerId),
      byConfidence: countBy(intel, (r) => r.confidence),
      expired: intel.filter((r) => r.expiresAt && new Date(r.expiresAt) < new Date()).length,
    });
  }
  return apiRequest<IntelligenceAnalytics>("/api/v1/analytics/intelligence", { searchParams: { target_id: targetId } });
}

export async function getAIAnalytics(targetId: string, range: RangePreset = "30d"): Promise<AIAnalytics> {
  if (USE_MOCKS) {
    const toolCalls = mockToolCalls.filter((t) => t.targetId === targetId);
    const results = mockAiResults;
    return mockDelay({
      requestsOverTime: bucketByDay(results, (r) => r.createdAt, Math.min(rangeToDays(range), 30)),
      byTaskType: countBy(results, (r) => r.taskType),
      byProvider: countBy(results, (r) => r.provider),
      averageLatencyMs: results.length ? Math.round(results.reduce((s, r) => s + r.latencyMs, 0) / results.length) : 0,
      inputTokens: results.reduce((s, r) => s + r.inputTokens, 0),
      outputTokens: results.reduce((s, r) => s + r.outputTokens, 0),
      failures: 0,
      toolCallsByTool: countBy(toolCalls, (t) => t.tool),
    });
  }
  return apiRequest<AIAnalytics>("/api/v1/analytics/ai", { searchParams: { target_id: targetId, range } });
}

export async function getSecurityPosture(targetId: string): Promise<SecurityPosture> {
  if (USE_MOCKS) {
    const risk = mockRiskScores.filter((r) => r.targetId === targetId);
    const avg = risk.length ? risk.reduce((s, r) => s + r.score, 0) / risk.length : 0;
    return mockDelay({
      score: Math.round(100 - avg),
      scoredEntities: risk.length,
      criticalCount: risk.filter((r) => r.severity === "critical").length,
      highCount: risk.filter((r) => r.severity === "high").length,
    });
  }
  return apiRequest<SecurityPosture>("/api/v1/analytics/posture", { searchParams: { target_id: targetId } });
}
