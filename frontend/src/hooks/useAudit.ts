import { useQuery } from "@tanstack/react-query";
import { useCurrentTargetId } from "./useWorkspace";
import { listAuditEvents } from "@/api/audit";
import type { PageParams } from "@/types/common";

export function useAuditEvents(page?: PageParams) {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["audit", targetId, page],
    queryFn: () => listAuditEvents(targetId!, page),
    enabled: !!targetId,
    placeholderData: (prev) => prev,
  });
}
