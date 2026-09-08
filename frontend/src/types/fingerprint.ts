/** Mirrors internal/domain/fingerprint.Fingerprint — backs the
 * Technologies page (spec §24). */

export type FingerprintCategory =
  | "web_server"
  | "reverse_proxy"
  | "framework"
  | "frontend"
  | "runtime"
  | "programming_language"
  | "cms"
  | "api"
  | "cloud"
  | "cdn"
  | "database"
  | "authentication"
  | "monitoring"
  | "analytics"
  | "ai_provider"
  | "ai_platform"
  | "ai_model_candidate"
  | "service"
  | "library"
  | "infrastructure";

/** Corrected after backend inspection during API wiring: the real
 * internal/domain/fingerprint.Status enum is only ACTIVE/INACTIVE — an
 * earlier added/confirmed/changed/removed lifecycle was invented before
 * this API existed and didn't match. */
export type FingerprintStatus = "ACTIVE" | "INACTIVE";

export interface Fingerprint {
  id: string;
  assetId: string;
  targetId: string;
  category: FingerprintCategory;
  technology: string;
  product: string;
  vendor: string;
  version: string;
  confidence: number; // 0.0-1.0
  status: FingerprintStatus;
  firstSeen: string;
  lastSeen: string;
}

/** A technology rolled up across every asset that runs it — the shape
 * the Technologies page actually displays (spec §24: "technology,
 * version, affected assets, risk, first seen, last seen"). */
export interface TechnologySummary {
  technology: string;
  category: FingerprintCategory;
  versions: string[];
  affectedAssetCount: number;
  criticalFindings: number;
  firstSeen: string;
  lastSeen: string;
}
