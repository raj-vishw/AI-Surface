/** Global search (spec §52) across the entities this backend actually
 * models. No dedicated backend search endpoint exists — this queries
 * each resource's own list, client-side, the same way the CLI has no
 * cross-entity search command either. A real implementation would add
 * GET /api/v1/search?q=... server-side (Postgres full-text or trigram)
 * rather than fan out N queries — documented as a "Backend Changes
 * Required" item in the frontend implementation report. */
import { USE_MOCKS, mockDelay } from "./config";
import { apiRequest } from "./client";
import {
  assets as mockAssets,
  findings as mockFindings,
  alerts as mockAlerts,
  investigations as mockInvestigations,
  incidentClusters as mockClusters,
  intelligenceRecords as mockIntel,
} from "@/mocks/database";
import { assetDisplayName } from "@/types/asset";

export interface SearchResultGroup {
  entity: "assets" | "findings" | "alerts" | "investigations" | "incidents" | "intelligence";
  label: string;
  results: { id: string; title: string; subtitle: string; href: string }[];
}

export async function globalSearch(targetId: string, query: string): Promise<SearchResultGroup[]> {
  const compute = (): SearchResultGroup[] => {
    const q = query.trim().toLowerCase();
    if (!q) return [];

    const assets = mockAssets
      .filter((a) => a.targetId === targetId && assetDisplayName(a).toLowerCase().includes(q))
      .slice(0, 5)
      .map((a) => ({ id: a.id, title: assetDisplayName(a), subtitle: a.type, href: `/assets/${a.id}` }));

    const findings = mockFindings
      .filter((f) => f.targetId === targetId && f.title.toLowerCase().includes(q))
      .slice(0, 5)
      .map((f) => ({ id: f.id, title: f.title, subtitle: f.severity, href: `/findings/${f.id}` }));

    const alerts = mockAlerts
      .filter((a) => a.targetId === targetId && a.title.toLowerCase().includes(q))
      .slice(0, 5)
      .map((a) => ({ id: a.id, title: a.title, subtitle: a.severity, href: `/alerts` }));

    const investigations = mockInvestigations
      .filter((i) => i.targetId === targetId && i.title.toLowerCase().includes(q))
      .slice(0, 5)
      .map((i) => ({ id: i.id, title: i.title, subtitle: i.status, href: `/investigations/${i.id}` }));

    const incidents = mockClusters
      .filter((c) => c.targetId === targetId && c.title.toLowerCase().includes(q))
      .slice(0, 5)
      .map((c) => ({ id: c.id, title: c.title, subtitle: c.status, href: `/incidents/${c.id}` }));

    const intelligence = mockIntel
      .filter((r) => r.targetId === targetId && r.indicatorValue.toLowerCase().includes(q))
      .slice(0, 5)
      .map((r) => ({ id: r.id, title: r.indicatorValue, subtitle: r.indicatorType, href: `/intelligence` }));

    const groups: SearchResultGroup[] = [
      { entity: "assets", label: "Assets", results: assets },
      { entity: "findings", label: "Findings", results: findings },
      { entity: "alerts", label: "Alerts", results: alerts },
      { entity: "investigations", label: "Investigations", results: investigations },
      { entity: "incidents", label: "Incidents", results: incidents },
      { entity: "intelligence", label: "Intelligence", results: intelligence },
    ];
    return groups.filter((g) => g.results.length > 0);
  };

  if (USE_MOCKS) return mockDelay(compute(), 120);
  return apiRequest<SearchResultGroup[]>("/api/v1/search", { searchParams: { target_id: targetId, q: query } });
}
