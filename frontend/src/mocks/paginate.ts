import type { Page, PageParams } from "@/types/common";
import { mockDelay } from "@/api/config";

/** Mirrors internal/repository/pagination.Page[T]'s cursor-based shape:
 * no total count (keyset pagination never computes one — see
 * types/common.ts's Page<T> doc comment), applied over an in-memory
 * mock array via a simple numeric-offset cursor. */
export function paginate<T>(items: T[], params: PageParams = {}): Page<T> {
  const limit = params.limit ?? 25;
  const start = params.cursor ? Number(params.cursor) : 0;
  const page = items.slice(start, start + limit);
  const hasMore = start + limit < items.length;
  return {
    items: page,
    hasMore,
    nextCursor: hasMore ? String(start + limit) : undefined,
  };
}

export function mockPage<T>(items: T[], params?: PageParams): Promise<Page<T>> {
  return mockDelay(paginate(items, params));
}
