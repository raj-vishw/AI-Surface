/** Proposed REST contract: GET /api/v1/incident-clusters — maps to
 * `ai-recon investigate suggest-clusters` / `... accept-cluster`. An
 * "incident" in this backend IS an accepted IncidentCluster (which
 * becomes an Investigation) — there is no separate incident table (see
 * docs/reporting/reports.md's "Investigation/Incident consolidation"
 * note). */
import { USE_MOCKS, mockDelay } from "./config";
import { apiRequest } from "./client";
import { incidentClusters as mockClusters } from "@/mocks/database";
import type { IncidentCluster, ClusterStatus } from "@/types/investigation";

export async function listIncidentClusters(targetId: string, status?: ClusterStatus): Promise<IncidentCluster[]> {
  if (USE_MOCKS) {
    let items = mockClusters.filter((c) => c.targetId === targetId);
    if (status) items = items.filter((c) => c.status === status);
    return mockDelay([...items].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)));
  }
  return apiRequest<IncidentCluster[]>("/api/v1/incident-clusters", { searchParams: { target_id: targetId, status } });
}

export async function getIncidentCluster(id: string): Promise<IncidentCluster | undefined> {
  if (USE_MOCKS) return mockDelay(mockClusters.find((c) => c.id === id));
  return apiRequest<IncidentCluster>(`/api/v1/incident-clusters/${id}`);
}
