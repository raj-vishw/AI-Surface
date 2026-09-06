import { useQuery } from "@tanstack/react-query";
import { useCurrentTargetId } from "./useWorkspace";
import { listFindings, getFinding, type FindingFilters } from "@/api/findings";
import type { PageParams } from "@/types/common";

export function useFindings(filters: FindingFilters = {}, page?: PageParams) {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["findings", targetId, filters, page],
    queryFn: () => listFindings(targetId!, filters, page),
    enabled: !!targetId,
    placeholderData: (prev) => prev,
  });
}

export function useFinding(id: string | undefined) {
  return useQuery({
    queryKey: ["finding", id],
    queryFn: () => getFinding(id!),
    enabled: !!id,
  });
}
