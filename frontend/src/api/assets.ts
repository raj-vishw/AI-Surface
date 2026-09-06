/** Proposed REST contract: GET /api/v1/assets, GET /api/v1/assets/:id
 * — maps to `ai-recon asset list` / `ai-recon asset get`. */
import { USE_MOCKS, mockDelay } from "./config";
import { apiRequest } from "./client";
import { mockPage } from "@/mocks/paginate";
import { assets as mockAssets, fingerprints as mockFingerprints, findings as mockFindings } from "@/mocks/database";
import type { Asset, AssetType, AssetStatus } from "@/types/asset";
import type { Fingerprint } from "@/types/fingerprint";
import type { Finding } from "@/types/finding";
import type { Page, PageParams } from "@/types/common";

export interface AssetFilters {
  type?: AssetType;
  status?: AssetStatus;
  search?: string;
}

export async function listAssets(
  targetId: string,
  filters: AssetFilters = {},
  page?: PageParams,
): Promise<Page<Asset>> {
  if (USE_MOCKS) {
    let items = mockAssets.filter((a) => a.targetId === targetId);
    if (filters.type) items = items.filter((a) => a.type === filters.type);
    if (filters.status) items = items.filter((a) => a.status === filters.status);
    if (filters.search) {
      const q = filters.search.toLowerCase();
      items = items.filter((a) =>
        [a.hostname, a.ip, a.url, a.technology].some((f) => f?.toLowerCase().includes(q)),
      );
    }
    return mockPage(items, page);
  }
  return apiRequest<Page<Asset>>("/api/v1/assets", {
    searchParams: { target_id: targetId, ...filters, limit: page?.limit, cursor: page?.cursor },
  });
}

export async function getAsset(id: string): Promise<Asset | undefined> {
  if (USE_MOCKS) return mockDelay(mockAssets.find((a) => a.id === id));
  return apiRequest<Asset>(`/api/v1/assets/${id}`);
}

export async function getAssetFingerprints(assetId: string): Promise<Fingerprint[]> {
  if (USE_MOCKS) return mockDelay(mockFingerprints.filter((f) => f.assetId === assetId));
  return apiRequest<Fingerprint[]>(`/api/v1/assets/${assetId}/fingerprints`);
}

export async function getAssetFindings(assetId: string): Promise<Finding[]> {
  if (USE_MOCKS) return mockDelay(mockFindings.filter((f) => f.assetId === assetId));
  return apiRequest<Finding[]>(`/api/v1/assets/${assetId}/findings`);
}
