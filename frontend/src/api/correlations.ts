/** Proposed REST contract: GET /api/v1/correlations, GET /:id/graph,
 * GET /api/v1/attack-chains, GET /:id/stages — maps to `ai-recon
 * correlation list|graph` / `ai-recon chain list|show`. */
import { USE_MOCKS, mockDelay } from "./config";
import { apiRequest } from "./client";
import { mockPage } from "@/mocks/paginate";
import {
  correlations as mockCorrelations,
  correlationNodes as mockNodes,
  correlationEdges as mockEdges,
  attackChains as mockChains,
  attackChainStages as mockStages,
} from "@/mocks/database";
import type {
  Correlation,
  CorrelationNode,
  CorrelationEdge,
  AttackChain,
  AttackChainStage,
  CorrelationStatus,
} from "@/types/correlation";
import type { Page, PageParams } from "@/types/common";

export async function listCorrelations(
  targetId: string,
  status?: CorrelationStatus,
  page?: PageParams,
): Promise<Page<Correlation>> {
  if (USE_MOCKS) {
    let items = mockCorrelations.filter((c) => c.targetId === targetId);
    if (status) items = items.filter((c) => c.status === status);
    items = [...items].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    return mockPage(items, page);
  }
  return apiRequest<Page<Correlation>>("/api/v1/correlations", {
    searchParams: { target_id: targetId, status, limit: page?.limit, cursor: page?.cursor },
  });
}

export async function getCorrelation(id: string): Promise<Correlation | undefined> {
  if (USE_MOCKS) return mockDelay(mockCorrelations.find((c) => c.id === id));
  return apiRequest<Correlation>(`/api/v1/correlations/${id}`);
}

export interface CorrelationGraph {
  nodes: CorrelationNode[];
  edges: CorrelationEdge[];
}

export async function getCorrelationGraph(id: string): Promise<CorrelationGraph> {
  if (USE_MOCKS) {
    return mockDelay({
      nodes: mockNodes.filter((n) => n.correlationId === id),
      edges: mockEdges.filter((e) => e.correlationId === id),
    });
  }
  return apiRequest<CorrelationGraph>(`/api/v1/correlations/${id}/graph`);
}

export async function listAttackChains(targetId: string): Promise<AttackChain[]> {
  if (USE_MOCKS) {
    const correlationIds = new Set(mockCorrelations.filter((c) => c.targetId === targetId).map((c) => c.id));
    return mockDelay(mockChains.filter((c) => correlationIds.has(c.correlationId)));
  }
  return apiRequest<AttackChain[]>("/api/v1/attack-chains", { searchParams: { target_id: targetId } });
}

export async function getAttackChain(id: string): Promise<AttackChain | undefined> {
  if (USE_MOCKS) return mockDelay(mockChains.find((c) => c.id === id));
  return apiRequest<AttackChain>(`/api/v1/attack-chains/${id}`);
}

export async function getAttackChainStages(chainId: string): Promise<AttackChainStage[]> {
  if (USE_MOCKS) {
    return mockDelay(mockStages.filter((s) => s.attackChainId === chainId).sort((a, b) => a.order - b.order));
  }
  return apiRequest<AttackChainStage[]>(`/api/v1/attack-chains/${chainId}/stages`);
}
