import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { useCurrentTargetId } from "./useWorkspace";
import { listScans, startScan } from "@/api/scans";
import type { ScanType } from "@/types/scan";
import type { PageParams } from "@/types/common";

export function useScans(page?: PageParams) {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["scans", targetId, page],
    queryFn: () => listScans(targetId!, page),
    enabled: !!targetId,
    placeholderData: (prev) => prev,
    // Scans transition state on their own in the mock layer; poll gently
    // rather than adding WebSocket infrastructure for a backend that has
    // no async job queue to push updates from yet (spec §55).
    refetchInterval: 5000,
  });
}

export function useStartScan() {
  const targetId = useCurrentTargetId();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ targetValue, scanType }: { targetValue: string; scanType: ScanType }) =>
      startScan(targetId!, targetValue, scanType),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      toast.success("Scan started");
    },
    onError: () => toast.error("Failed to start scan"),
  });
}
