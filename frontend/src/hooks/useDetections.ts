import { useQuery } from "@tanstack/react-query";
import { useCurrentTargetId } from "./useWorkspace";
import { listRules, getRule, listDetectionMatches } from "@/api/detections";
import type { RuleStatus } from "@/types/detection";
import type { PageParams } from "@/types/common";

export function useRules(status?: RuleStatus) {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["rules", targetId, status],
    queryFn: () => listRules(targetId!, status),
    enabled: !!targetId,
  });
}

export function useRule(id: string | undefined) {
  return useQuery({ queryKey: ["rule", id], queryFn: () => getRule(id!), enabled: !!id });
}

export function useDetectionMatches(page?: PageParams) {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["detection-matches", targetId, page],
    queryFn: () => listDetectionMatches(targetId!, page),
    enabled: !!targetId,
    placeholderData: (prev) => prev,
  });
}
