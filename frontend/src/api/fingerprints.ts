/** Proposed REST contract: GET /api/v1/technologies — a rollup over
 * `ai-recon fingerprint list`'s Fingerprint rows, grouped by technology
 * (spec §24's "technology, version, affected assets, risk, first seen,
 * last seen" is a rollup, not a single row's shape). */
import { USE_MOCKS, mockDelay } from "./config";
import { apiRequest } from "./client";
import { fingerprints as mockFingerprints, findings as mockFindings } from "@/mocks/database";
import type { TechnologySummary } from "@/types/fingerprint";

export async function listTechnologies(targetId: string): Promise<TechnologySummary[]> {
  if (USE_MOCKS) {
    const fps = mockFingerprints.filter((f) => f.targetId === targetId && f.status !== "removed");
    const byTech = new Map<string, TechnologySummary>();
    for (const fp of fps) {
      const existing = byTech.get(fp.technology);
      const criticalFindings = mockFindings.filter(
        (find) => find.assetId === fp.assetId && (find.severity === "critical" || find.severity === "high") && find.status === "open",
      ).length;
      if (!existing) {
        byTech.set(fp.technology, {
          technology: fp.technology,
          category: fp.category,
          versions: fp.version ? [fp.version] : [],
          affectedAssetCount: 1,
          criticalFindings,
          firstSeen: fp.firstSeen,
          lastSeen: fp.lastSeen,
        });
      } else {
        existing.affectedAssetCount += 1;
        existing.criticalFindings += criticalFindings;
        if (fp.version && !existing.versions.includes(fp.version)) existing.versions.push(fp.version);
        if (fp.firstSeen < existing.firstSeen) existing.firstSeen = fp.firstSeen;
        if (fp.lastSeen > existing.lastSeen) existing.lastSeen = fp.lastSeen;
      }
    }
    return mockDelay([...byTech.values()].sort((a, b) => b.affectedAssetCount - a.affectedAssetCount));
  }
  return apiRequest<TechnologySummary[]>("/api/v1/technologies", { searchParams: { target_id: targetId } });
}
