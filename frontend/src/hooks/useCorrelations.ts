import { useQuery } from "@tanstack/react-query";
import { useCurrentTargetId } from "./useWorkspace";
import {
  listCorrelations,
  getCorrelation,
  getCorrelationGraph,
  listAttackChains,
  getAttackChain,
  getAttackChainStages,
} from "@/api/correlations";
import type { CorrelationStatus } from "@/types/correlation";
import type { PageParams } from "@/types/common";

export function useCorrelations(status?: CorrelationStatus, page?: PageParams) {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["correlations", targetId, status, page],
    queryFn: () => listCorrelations(targetId!, status, page),
    enabled: !!targetId,
    placeholderData: (prev) => prev,
  });
}

export function useCorrelation(id: string | undefined) {
  return useQuery({ queryKey: ["correlation", id], queryFn: () => getCorrelation(id!), enabled: !!id });
}

export function useCorrelationGraph(id: string | undefined) {
  return useQuery({ queryKey: ["correlation-graph", id], queryFn: () => getCorrelationGraph(id!), enabled: !!id });
}

export function useAttackChains() {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["attack-chains", targetId],
    queryFn: () => listAttackChains(targetId!),
    enabled: !!targetId,
  });
}

export function useAttackChain(id: string | undefined) {
  return useQuery({ queryKey: ["attack-chain", id], queryFn: () => getAttackChain(id!), enabled: !!id });
}

export function useAttackChainStages(chainId: string | undefined) {
  return useQuery({
    queryKey: ["attack-chain-stages", chainId],
    queryFn: () => getAttackChainStages(chainId!),
    enabled: !!chainId,
  });
}
