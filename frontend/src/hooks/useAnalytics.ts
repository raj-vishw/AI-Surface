import { useQuery } from "@tanstack/react-query";
import { useCurrentTargetId } from "./useWorkspace";
import * as analyticsApi from "@/api/analytics";
import type { RangePreset } from "@/types/analytics";

const staleTime = 30_000; // mirrors internal/analytics.Cache's 30s default TTL

export function useOverview() {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["analytics-overview", targetId],
    queryFn: () => analyticsApi.getOverview(targetId!),
    enabled: !!targetId,
    staleTime,
  });
}

export function useRiskAnalytics(range: RangePreset = "30d") {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["analytics-risk", targetId, range],
    queryFn: () => analyticsApi.getRiskAnalytics(targetId!, range),
    enabled: !!targetId,
    staleTime,
  });
}

export function useAlertAnalytics(range: RangePreset = "30d") {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["analytics-alerts", targetId, range],
    queryFn: () => analyticsApi.getAlertAnalytics(targetId!, range),
    enabled: !!targetId,
    staleTime,
  });
}

export function useDetectionAnalytics(range: RangePreset = "30d") {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["analytics-detections", targetId, range],
    queryFn: () => analyticsApi.getDetectionAnalytics(targetId!, range),
    enabled: !!targetId,
    staleTime,
  });
}

export function useFindingAnalytics(range: RangePreset = "30d") {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["analytics-findings", targetId, range],
    queryFn: () => analyticsApi.getFindingAnalytics(targetId!, range),
    enabled: !!targetId,
    staleTime,
  });
}

export function useAssetAnalytics() {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["analytics-assets", targetId],
    queryFn: () => analyticsApi.getAssetAnalytics(targetId!),
    enabled: !!targetId,
    staleTime,
  });
}

export function useAttackSurfaceTrend(range: RangePreset = "30d") {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["analytics-attack-surface", targetId, range],
    queryFn: () => analyticsApi.getAttackSurfaceTrend(targetId!, range),
    enabled: !!targetId,
    staleTime,
  });
}

export function useCorrelationAnalytics(range: RangePreset = "30d") {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["analytics-correlations", targetId, range],
    queryFn: () => analyticsApi.getCorrelationAnalytics(targetId!, range),
    enabled: !!targetId,
    staleTime,
  });
}

export function useInvestigationAnalytics(range: RangePreset = "30d") {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["analytics-investigations", targetId, range],
    queryFn: () => analyticsApi.getInvestigationAnalytics(targetId!, range),
    enabled: !!targetId,
    staleTime,
  });
}

export function useIntelligenceAnalytics() {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["analytics-intelligence", targetId],
    queryFn: () => analyticsApi.getIntelligenceAnalytics(targetId!),
    enabled: !!targetId,
    staleTime,
  });
}

export function useAIAnalytics(range: RangePreset = "30d") {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["analytics-ai", targetId, range],
    queryFn: () => analyticsApi.getAIAnalytics(targetId!, range),
    enabled: !!targetId,
    staleTime,
  });
}

export function useSecurityPosture() {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["analytics-posture", targetId],
    queryFn: () => analyticsApi.getSecurityPosture(targetId!),
    enabled: !!targetId,
    staleTime,
  });
}
