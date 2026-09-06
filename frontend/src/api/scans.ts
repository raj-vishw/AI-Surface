/** Proposed REST contract: GET /api/v1/scans, POST /api/v1/scans — maps
 * to `ai-recon scan|network-scan|dns-scan|endpoint-scan|fingerprint`.
 * See src/types/scan.ts's header comment: this backend runs these
 * commands SYNCHRONOUSLY today (no async job queue exists — cmd/worker
 * has no job consumer). The "queued/running" states this API returns
 * anticipate a future async execution model; a real integration today
 * would call the CLI and immediately receive a "completed" or "failed"
 * result rather than polling. */
import { USE_MOCKS, mockDelay } from "./config";
import { apiRequest } from "./client";
import { mockPage } from "@/mocks/paginate";
import { scans as mockScans } from "@/mocks/database";
import { mockId } from "@/mocks/random";
import type { Scan, ScanType } from "@/types/scan";
import type { Page, PageParams } from "@/types/common";

export async function listScans(targetId: string, page?: PageParams): Promise<Page<Scan>> {
  if (USE_MOCKS) {
    const items = [...mockScans.filter((s) => s.targetId === targetId)].sort((a, b) => b.startedAt.localeCompare(a.startedAt));
    return mockPage(items, page);
  }
  return apiRequest<Page<Scan>>("/api/v1/scans", { searchParams: { target_id: targetId, limit: page?.limit, cursor: page?.cursor } });
}

export async function startScan(targetId: string, targetValue: string, scanType: ScanType): Promise<Scan> {
  if (USE_MOCKS) {
    const scan: Scan = {
      id: mockId("scan-new"),
      targetId,
      targetValue,
      scanType,
      status: "running",
      startedAt: new Date().toISOString(),
      completedAt: null,
      durationMs: null,
      assetsDiscovered: 0,
      findingsDiscovered: 0,
      error: null,
    };
    mockScans.unshift(scan);
    return mockDelay(scan, 400);
  }
  return apiRequest<Scan>("/api/v1/scans", { method: "POST", body: { target_id: targetId, scan_type: scanType } });
}
