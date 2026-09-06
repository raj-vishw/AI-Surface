/** Proposed REST contract: GET /api/v1/evidence-packages — maps to
 * `ai-recon evidence-package create|list|show` (Phase 14). */
import { USE_MOCKS, mockDelay } from "./config";
import { apiRequest } from "./client";
import { evidencePackages as mockPackages, reports as mockReports } from "@/mocks/database";
import type { EvidencePackage } from "@/types/reporting";

export interface EvidencePackageWithReport extends EvidencePackage {
  reportTitle: string;
}

export async function listEvidencePackages(targetId: string): Promise<EvidencePackageWithReport[]> {
  if (USE_MOCKS) {
    const items = mockPackages
      .filter((p) => p.targetId === targetId)
      .map((p) => ({ ...p, reportTitle: mockReports.find((r) => r.id === p.reportId)?.title ?? "Unknown report" }));
    return mockDelay(items);
  }
  return apiRequest<EvidencePackageWithReport[]>("/api/v1/evidence-packages", { searchParams: { target_id: targetId } });
}
