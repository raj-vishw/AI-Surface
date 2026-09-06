/** Proposed REST contract: GET /api/v1/targets, GET /api/v1/targets/:id
 * — maps 1:1 to `ai-recon target list` / `ai-recon target create` /
 * `ai-recon target authorize`. See src/api/config.ts's header comment. */
import { USE_MOCKS, mockDelay } from "./config";
import { apiRequest } from "./client";
import { targets as mockTargets } from "@/mocks/database";
import type { Target } from "@/types/target";

export async function listTargets(): Promise<Target[]> {
  if (USE_MOCKS) return mockDelay(mockTargets);
  return apiRequest<Target[]>("/api/v1/targets");
}

export async function getTarget(id: string): Promise<Target | undefined> {
  if (USE_MOCKS) return mockDelay(mockTargets.find((t) => t.id === id));
  return apiRequest<Target>(`/api/v1/targets/${id}`);
}
