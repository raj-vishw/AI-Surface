/** Proposed REST contract: GET /api/v1/alerts, PATCH /api/v1/alerts/:id
 * — maps to `ai-recon alert list` / `ai-recon alert acknowledge|resolve|
 * dismiss` (Phase 11's alert lifecycle — see docs/architecture/
 * detection-engine.md). Mutations are implemented against the mock
 * store (in-memory) so the UI's acknowledge/resolve/dismiss actions are
 * genuinely functional in development, not decorative. */
import { USE_MOCKS, mockDelay } from "./config";
import { apiRequest } from "./client";
import { mockPage } from "@/mocks/paginate";
import { alerts as mockAlerts } from "@/mocks/database";
import type { Alert, AlertStatus } from "@/types/detection";
import type { Severity } from "@/lib/severity";
import type { Page, PageParams } from "@/types/common";

export interface AlertFilters {
  severity?: Severity;
  status?: AlertStatus;
}

export async function listAlerts(targetId: string, filters: AlertFilters = {}, page?: PageParams): Promise<Page<Alert>> {
  if (USE_MOCKS) {
    let items = mockAlerts.filter((a) => a.targetId === targetId);
    if (filters.severity) items = items.filter((a) => a.severity === filters.severity);
    if (filters.status) items = items.filter((a) => a.status === filters.status);
    items = [...items].sort((a, b) => b.lastObservedAt.localeCompare(a.lastObservedAt));
    return mockPage(items, page);
  }
  return apiRequest<Page<Alert>>("/api/v1/alerts", {
    searchParams: { target_id: targetId, ...filters, limit: page?.limit, cursor: page?.cursor },
  });
}

async function setAlertStatus(id: string, status: AlertStatus): Promise<Alert> {
  if (USE_MOCKS) {
    const alert = mockAlerts.find((a) => a.id === id);
    if (!alert) throw new Error("alert not found");
    alert.status = status;
    alert.updatedAt = new Date().toISOString();
    return mockDelay({ ...alert });
  }
  return apiRequest<Alert>(`/api/v1/alerts/${id}`, { method: "PATCH", body: { status } });
}

export const acknowledgeAlert = (id: string) => setAlertStatus(id, "acknowledged");
export const investigateAlert = (id: string) => setAlertStatus(id, "investigating");
export const resolveAlert = (id: string) => setAlertStatus(id, "resolved");
export const dismissAlert = (id: string) => setAlertStatus(id, "suppressed");
