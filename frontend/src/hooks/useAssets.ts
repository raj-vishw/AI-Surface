import { useQuery } from "@tanstack/react-query";
import { useCurrentTargetId } from "./useWorkspace";
import { listAssets, getAsset, getAssetFingerprints, getAssetFindings, type AssetFilters } from "@/api/assets";
import type { PageParams } from "@/types/common";

export function useAssets(filters: AssetFilters = {}, page?: PageParams) {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["assets", targetId, filters, page],
    queryFn: () => listAssets(targetId!, filters, page),
    enabled: !!targetId,
    placeholderData: (prev) => prev,
  });
}

export function useAsset(id: string | undefined) {
  return useQuery({
    queryKey: ["asset", id],
    queryFn: () => getAsset(id!),
    enabled: !!id,
  });
}

export function useAssetFingerprints(assetId: string | undefined) {
  return useQuery({
    queryKey: ["asset-fingerprints", assetId],
    queryFn: () => getAssetFingerprints(assetId!),
    enabled: !!assetId,
  });
}

export function useAssetFindings(assetId: string | undefined) {
  return useQuery({
    queryKey: ["asset-findings", assetId],
    queryFn: () => getAssetFindings(assetId!),
    enabled: !!assetId,
  });
}
