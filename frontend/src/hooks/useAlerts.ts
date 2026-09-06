import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { useCurrentTargetId } from "./useWorkspace";
import {
  listAlerts,
  acknowledgeAlert,
  investigateAlert,
  resolveAlert,
  dismissAlert,
  type AlertFilters,
} from "@/api/alerts";
import type { PageParams } from "@/types/common";

export function useAlerts(filters: AlertFilters = {}, page?: PageParams) {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["alerts", targetId, filters, page],
    queryFn: () => listAlerts(targetId!, filters, page),
    enabled: !!targetId,
    placeholderData: (prev) => prev,
  });
}

export function useAlertActions() {
  const queryClient = useQueryClient();
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["alerts"] });

  const acknowledge = useMutation({
    mutationFn: acknowledgeAlert,
    onSuccess: () => {
      invalidate();
      toast.success("Alert acknowledged");
    },
    onError: () => toast.error("Failed to acknowledge alert"),
  });
  const investigate = useMutation({
    mutationFn: investigateAlert,
    onSuccess: () => {
      invalidate();
      toast.success("Alert marked as investigating");
    },
    onError: () => toast.error("Failed to update alert"),
  });
  const resolve = useMutation({
    mutationFn: resolveAlert,
    onSuccess: () => {
      invalidate();
      toast.success("Alert resolved");
    },
    onError: () => toast.error("Failed to resolve alert"),
  });
  const dismiss = useMutation({
    mutationFn: dismissAlert,
    onSuccess: () => {
      invalidate();
      toast.success("Alert dismissed");
    },
    onError: () => toast.error("Failed to dismiss alert"),
  });

  return { acknowledge, investigate, resolve, dismiss };
}
