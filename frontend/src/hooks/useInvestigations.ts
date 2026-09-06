import { useQuery } from "@tanstack/react-query";
import { useCurrentTargetId } from "./useWorkspace";
import {
  listInvestigations,
  getInvestigation,
  getInvestigationTimeline,
  getInvestigationNotes,
  getInvestigationHypotheses,
  type InvestigationFilters,
} from "@/api/investigations";
import type { PageParams } from "@/types/common";

export function useInvestigations(filters: InvestigationFilters = {}, page?: PageParams) {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["investigations", targetId, filters, page],
    queryFn: () => listInvestigations(targetId!, filters, page),
    enabled: !!targetId,
    placeholderData: (prev) => prev,
  });
}

export function useInvestigation(id: string | undefined) {
  return useQuery({ queryKey: ["investigation", id], queryFn: () => getInvestigation(id!), enabled: !!id });
}

export function useInvestigationTimeline(id: string | undefined) {
  return useQuery({ queryKey: ["investigation-timeline", id], queryFn: () => getInvestigationTimeline(id!), enabled: !!id });
}

export function useInvestigationNotes(id: string | undefined) {
  return useQuery({ queryKey: ["investigation-notes", id], queryFn: () => getInvestigationNotes(id!), enabled: !!id });
}

export function useInvestigationHypotheses(id: string | undefined) {
  return useQuery({ queryKey: ["investigation-hypotheses", id], queryFn: () => getInvestigationHypotheses(id!), enabled: !!id });
}
