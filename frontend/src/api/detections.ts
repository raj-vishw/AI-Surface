/** Proposed REST contract: GET /api/v1/rules, GET /api/v1/detection-matches
 * — maps to `ai-recon detection rules`/`ai-recon detection matches`. */
import { USE_MOCKS, mockDelay } from "./config";
import { apiRequest } from "./client";
import { mockPage } from "@/mocks/paginate";
import { rules as mockRules, detectionMatches as mockMatches } from "@/mocks/database";
import type { Rule, DetectionMatch, RuleStatus } from "@/types/detection";
import type { Page, PageParams } from "@/types/common";

export async function listRules(targetId: string, status?: RuleStatus): Promise<Rule[]> {
  if (USE_MOCKS) {
    let items = mockRules.filter((r) => r.targetId === targetId);
    if (status) items = items.filter((r) => r.status === status);
    return mockDelay(items);
  }
  return apiRequest<Rule[]>("/api/v1/rules", { searchParams: { target_id: targetId, status } });
}

export async function getRule(id: string): Promise<Rule | undefined> {
  if (USE_MOCKS) return mockDelay(mockRules.find((r) => r.id === id));
  return apiRequest<Rule>(`/api/v1/rules/${id}`);
}

export async function listDetectionMatches(targetId: string, page?: PageParams): Promise<Page<DetectionMatch>> {
  if (USE_MOCKS) {
    const items = [...mockMatches.filter((m) => m.targetId === targetId)].sort((a, b) =>
      b.lastObservedAt.localeCompare(a.lastObservedAt),
    );
    return mockPage(items, page);
  }
  return apiRequest<Page<DetectionMatch>>("/api/v1/detection-matches", {
    searchParams: { target_id: targetId, limit: page?.limit, cursor: page?.cursor },
  });
}
