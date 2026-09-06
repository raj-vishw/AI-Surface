import { useQuery } from "@tanstack/react-query";
import { useCurrentTargetId } from "./useWorkspace";
import { globalSearch } from "@/api/search";

export function useGlobalSearch(query: string) {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["search", targetId, query],
    queryFn: () => globalSearch(targetId!, query),
    enabled: !!targetId && query.trim().length > 0,
  });
}
