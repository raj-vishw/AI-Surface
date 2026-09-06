import { useState } from "react";

/** Manages a stack of cursors so a cursor-paginated (forward-only, like
 * this backend's own pagination.Page[T]) list can still offer a
 * "Previous" control in the UI. */
export function useCursorPagination(limit = 20) {
  const [stack, setStack] = useState<string[]>([]);
  const cursor = stack[stack.length - 1];

  return {
    pageParams: { limit, cursor },
    hasPrev: stack.length > 0,
    next: (nextCursor: string | undefined) => {
      if (nextCursor) setStack((s) => [...s, nextCursor]);
    },
    prev: () => setStack((s) => s.slice(0, -1)),
    reset: () => setStack([]),
  };
}
