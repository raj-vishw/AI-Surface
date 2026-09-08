/** Shared primitive types mirroring backend conventions
 * (internal/repository/pagination.Page[T], apperrors.Error).
 *
 * `total` is deliberately absent: internal/repository/pagination.Page[T]
 * is pure keyset (cursor) pagination and never computes a full COUNT(*)
 * (that would defeat the point of keyset pagination on a large table —
 * see that package's own doc comment) — corrected here after backend
 * inspection during API wiring; the mock layer's earlier `total` field
 * was a frontend-only invention with no backend equivalent. */
export interface Page<T> {
  items: T[];
  hasMore: boolean;
  nextCursor?: string;
}

export interface PageParams {
  limit?: number;
  cursor?: string;
}

/** Mirrors internal/errors.Error's shape — category + safe client message. */
export interface ApiError {
  category:
    | "validation"
    | "not_found"
    | "forbidden"
    | "conflict"
    | "database"
    | "internal";
  message: string;
}

export type EntityType =
  | "asset"
  | "finding"
  | "alert"
  | "detection_match"
  | "correlation"
  | "attack_chain"
  | "investigation"
  | "incident_cluster"
  | "intelligence_record"
  | "event";
