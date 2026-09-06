import { useQuery } from "@tanstack/react-query";
import { useCurrentTargetId } from "./useWorkspace";
import { listIncidentClusters, getIncidentCluster } from "@/api/incidents";
import type { ClusterStatus } from "@/types/investigation";

export function useIncidentClusters(status?: ClusterStatus) {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["incident-clusters", targetId, status],
    queryFn: () => listIncidentClusters(targetId!, status),
    enabled: !!targetId,
  });
}

export function useIncidentCluster(id: string | undefined) {
  return useQuery({ queryKey: ["incident-cluster", id], queryFn: () => getIncidentCluster(id!), enabled: !!id });
}
