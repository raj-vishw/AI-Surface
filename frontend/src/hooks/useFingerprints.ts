import { useQuery } from "@tanstack/react-query";
import { useCurrentTargetId } from "./useWorkspace";
import { listTechnologies } from "@/api/fingerprints";

export function useTechnologies() {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["technologies", targetId],
    queryFn: () => listTechnologies(targetId!),
    enabled: !!targetId,
  });
}
