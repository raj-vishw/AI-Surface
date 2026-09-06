import { useQuery } from "@tanstack/react-query";
import { useCurrentTargetId } from "./useWorkspace";
import { listReports, getReport, listControlEvidence, type ReportFilters } from "@/api/reports";
import { listEvidencePackages } from "@/api/evidence";
import type { PageParams } from "@/types/common";

export function useReports(filters: ReportFilters = {}, page?: PageParams) {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["reports", targetId, filters, page],
    queryFn: () => listReports(targetId!, filters, page),
    enabled: !!targetId,
    placeholderData: (prev) => prev,
  });
}

export function useReport(id: string | undefined) {
  return useQuery({ queryKey: ["report", id], queryFn: () => getReport(id!), enabled: !!id });
}

export function useEvidencePackages() {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["evidence-packages", targetId],
    queryFn: () => listEvidencePackages(targetId!),
    enabled: !!targetId,
  });
}

export function useControlEvidence() {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["control-evidence", targetId],
    queryFn: () => listControlEvidence(targetId!),
    enabled: !!targetId,
  });
}
