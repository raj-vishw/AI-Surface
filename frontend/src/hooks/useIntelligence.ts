import { useQuery } from "@tanstack/react-query";
import { useCurrentTargetId } from "./useWorkspace";
import { listIntelligence, listRiskScores, type IntelFilters } from "@/api/intelligence";
import type { RiskScore } from "@/types/intelligence";
import type { PageParams } from "@/types/common";

export function useIntelligence(filters: IntelFilters = {}, page?: PageParams) {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["intelligence", targetId, filters, page],
    queryFn: () => listIntelligence(targetId!, filters, page),
    enabled: !!targetId,
    placeholderData: (prev) => prev,
  });
}

export function useRiskScores(entityType?: RiskScore["entityType"]) {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["risk-scores", targetId, entityType],
    queryFn: () => listRiskScores(targetId!, entityType),
    enabled: !!targetId,
  });
}
