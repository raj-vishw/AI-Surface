/** Proposed REST contract: GET /api/v1/reports, GET /:id, POST /:id/
 * approve, GET /:id/export — maps to `ai-recon report create|list|show|
 * approve|review|export` (Phase 14). */
import { USE_MOCKS, mockDelay } from "./config";
import { apiRequest } from "./client";
import { mockPage } from "@/mocks/paginate";
import { reports as mockReports, controlEvidence as mockControlEvidence } from "@/mocks/database";
import type { Report, ReportType, ReportStatus, ControlEvidence } from "@/types/reporting";
import type { Page, PageParams } from "@/types/common";

export interface ReportFilters {
  reportType?: ReportType;
  status?: ReportStatus;
}

export async function listReports(targetId: string, filters: ReportFilters = {}, page?: PageParams): Promise<Page<Report>> {
  if (USE_MOCKS) {
    let items = mockReports.filter((r) => r.targetId === targetId);
    if (filters.reportType) items = items.filter((r) => r.reportType === filters.reportType);
    if (filters.status) items = items.filter((r) => r.status === filters.status);
    items = [...items].sort((a, b) => b.generatedAt.localeCompare(a.generatedAt));
    return mockPage(items, page);
  }
  return apiRequest<Page<Report>>("/api/v1/reports", {
    searchParams: { target_id: targetId, ...filters, limit: page?.limit, cursor: page?.cursor },
  });
}

export async function getReport(id: string): Promise<Report | undefined> {
  if (USE_MOCKS) return mockDelay(mockReports.find((r) => r.id === id));
  return apiRequest<Report>(`/api/v1/reports/${id}`);
}

export async function listControlEvidence(targetId: string): Promise<ControlEvidence[]> {
  if (USE_MOCKS) return mockDelay(mockControlEvidence.filter((c) => c.targetId === targetId));
  return apiRequest<ControlEvidence[]>("/api/v1/controls", { searchParams: { target_id: targetId } });
}
