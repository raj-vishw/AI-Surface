/** This backend has no separate audit-log table — the investigation
 * timeline IS its audit trail (see docs/reporting/reports.md's "Audit
 * report" section, an established precedent since Phase 9/11/12/13).
 * Proposed REST contract: GET /api/v1/audit — a target-wide read across
 * every investigation's timeline, exactly what `ai-recon report create
 * --type audit` already does server-side. */
import { USE_MOCKS } from "./config";
import { apiRequest } from "./client";
import { mockPage } from "@/mocks/paginate";
import { timelineEvents as mockTimeline } from "@/mocks/database";
import type { TimelineEvent } from "@/types/investigation";
import type { Page, PageParams } from "@/types/common";

export async function listAuditEvents(targetId: string, page?: PageParams): Promise<Page<TimelineEvent>> {
  if (USE_MOCKS) {
    const items = [...mockTimeline.filter((t) => t.targetId === targetId)].sort((a, b) =>
      b.timestamp.localeCompare(a.timestamp),
    );
    return mockPage(items, page);
  }
  return apiRequest<Page<TimelineEvent>>("/api/v1/audit", { searchParams: { target_id: targetId, limit: page?.limit, cursor: page?.cursor } });
}
