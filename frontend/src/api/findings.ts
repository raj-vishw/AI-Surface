/** Proposed REST contract: GET /api/v1/findings, GET /api/v1/findings/:id
 * — maps to `ai-recon findings list` / `ai-recon findings get`. */
import { USE_MOCKS, mockDelay } from "./config";
import { apiRequest } from "./client";
import { mockPage } from "@/mocks/paginate";
import { findings as mockFindings } from "@/mocks/database";
import type { Finding, FindingCategory, FindingStatus } from "@/types/finding";
import type { Severity } from "@/lib/severity";
import type { Page, PageParams } from "@/types/common";

export interface FindingFilters {
  severity?: Severity;
  status?: FindingStatus;
  category?: FindingCategory;
  assetId?: string;
  search?: string;
}

export async function listFindings(
  targetId: string,
  filters: FindingFilters = {},
  page?: PageParams,
): Promise<Page<Finding>> {
  if (USE_MOCKS) {
    let items = mockFindings.filter((f) => f.targetId === targetId);
    if (filters.severity) items = items.filter((f) => f.severity === filters.severity);
    if (filters.status) items = items.filter((f) => f.status === filters.status);
    if (filters.category) items = items.filter((f) => f.category === filters.category);
    if (filters.assetId) items = items.filter((f) => f.assetId === filters.assetId);
    if (filters.search) {
      const q = filters.search.toLowerCase();
      items = items.filter((f) => f.title.toLowerCase().includes(q) || f.description.toLowerCase().includes(q));
    }
    items = [...items].sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));
    return mockPage(items, page);
  }
  return apiRequest<Page<Finding>>("/api/v1/findings", {
    searchParams: { target_id: targetId, ...filters, limit: page?.limit, cursor: page?.cursor },
  });
}

export async function getFinding(id: string): Promise<Finding | undefined> {
  if (USE_MOCKS) return mockDelay(mockFindings.find((f) => f.id === id));
  return apiRequest<Finding>(`/api/v1/findings/${id}`);
}
