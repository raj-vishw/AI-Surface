/** Proposed REST contract: GET /api/v1/intelligence — maps to `ai-recon
 * intel list|show`. */
import { USE_MOCKS, mockDelay } from "./config";
import { apiRequest } from "./client";
import { mockPage } from "@/mocks/paginate";
import { intelligenceRecords as mockRecords, riskScores as mockRiskScores } from "@/mocks/database";
import type { IntelligenceRecord, IndicatorType, RiskScore } from "@/types/intelligence";
import type { Page, PageParams } from "@/types/common";

export interface IntelFilters {
  indicatorType?: IndicatorType;
  maliciousOnly?: boolean;
}

export async function listIntelligence(
  targetId: string,
  filters: IntelFilters = {},
  page?: PageParams,
): Promise<Page<IntelligenceRecord>> {
  if (USE_MOCKS) {
    let items = mockRecords.filter((r) => r.targetId === targetId);
    if (filters.indicatorType) items = items.filter((r) => r.indicatorType === filters.indicatorType);
    if (filters.maliciousOnly) items = items.filter((r) => r.malicious);
    items = [...items].sort((a, b) => b.observedAt.localeCompare(a.observedAt));
    return mockPage(items, page);
  }
  return apiRequest<Page<IntelligenceRecord>>("/api/v1/intelligence", {
    searchParams: { target_id: targetId, ...filters, limit: page?.limit, cursor: page?.cursor },
  });
}

export async function listRiskScores(targetId: string, entityType?: RiskScore["entityType"]): Promise<RiskScore[]> {
  if (USE_MOCKS) {
    let items = mockRiskScores.filter((r) => r.targetId === targetId);
    if (entityType) items = items.filter((r) => r.entityType === entityType);
    return mockDelay(items);
  }
  return apiRequest<RiskScore[]>("/api/v1/risk-scores", { searchParams: { target_id: targetId, entity_type: entityType } });
}
