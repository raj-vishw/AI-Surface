/** Shared primitive types mirroring backend conventions
 * (internal/repository/pagination.Page[T], apperrors.Error). */

export interface Page<T> {
  items: T[];
  total: number;
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
