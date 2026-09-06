/** Mirrors internal/domain/asset.Asset. "Domains/Subdomains/IPs/Ports/
 * Services" (spec §9's suggested sidebar groups) are NOT separate backend
 * entities — they are all Asset rows distinguished by `type`, so the
 * frontend renders them as filtered views of one Assets page rather than
 * as separate resource types (see pages/Assets). */

export type AssetType =
  | "DOMAIN"
  | "SUBDOMAIN"
  | "HOST"
  | "IP"
  | "PORT"
  | "SERVICE"
  | "HTTP_ENDPOINT"
  | "API_ENDPOINT"
  | "AI_ENDPOINT"
  | "REPOSITORY"
  | "CLOUD_RESOURCE"
  | "MODEL_ENDPOINT";

export type AssetStatus =
  | "DISCOVERED"
  | "ACTIVE"
  | "INACTIVE"
  | "UNKNOWN"
  | "RETIRED";

export type ConfidenceLevelUpper = "UNKNOWN" | "LOW" | "MEDIUM" | "HIGH" | "CONFIRMED";

export interface Asset {
  id: string;
  targetId: string;
  type: AssetType;
  status: AssetStatus;
  confidence: number; // 0.0-1.0
  confidenceLevel: ConfidenceLevelUpper;

  hostname: string | null;
  ip: string | null;
  port: number | null;
  protocol: string | null;
  url: string | null;
  technology: string | null;
  provider: string | null;
  model: string | null;
  environment: string | null;

  source: string;
  identityKey: string;

  firstSeen: string;
  lastSeen: string;
  createdAt: string;
  updatedAt: string;

  metadata: Record<string, unknown>;
}

/** The value most useful to show as an asset's primary "name" in a table,
 * chosen by type — never invented, always one of the asset's own fields. */
export function assetDisplayName(a: Pick<Asset, "type" | "hostname" | "ip" | "url" | "port" | "protocol">): string {
  if (a.hostname) return a.hostname;
  if (a.url) return a.url;
  if (a.ip && a.port) return `${a.ip}:${a.port}${a.protocol ? ` (${a.protocol})` : ""}`;
  if (a.ip) return a.ip;
  return "—";
}
