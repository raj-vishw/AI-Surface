import { ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/Button";

interface PaginationProps {
  shown: number;
  hasMore: boolean;
  onNext: () => void;
  onPrev: () => void;
  hasPrev: boolean;
}

/** No total-count display: internal/repository/pagination.Page[T] is
 * pure keyset pagination and never computes a full COUNT(*) (see
 * frontend/src/types/common.ts's Page<T> doc comment) — "Showing N"
 * with a Next/Previous control is what a cursor-paginated API can
 * honestly support. */
export function Pagination({ shown, hasMore, onNext, onPrev, hasPrev }: PaginationProps) {
  return (
    <div className="flex items-center justify-between border-t border-[color:var(--color-border)] px-4 py-2.5 text-xs text-[color:var(--color-text-muted)]">
      <span>
        Showing <span className="font-technical text-[color:var(--color-text)]">{shown}</span>
        {hasMore ? " (more available)" : ""}
      </span>
      <div className="flex items-center gap-1.5">
        <Button variant="outline" size="sm" onClick={onPrev} disabled={!hasPrev}>
          <ChevronLeft className="size-3.5" /> Previous
        </Button>
        <Button variant="outline" size="sm" onClick={onNext} disabled={!hasMore}>
          Next <ChevronRight className="size-3.5" />
        </Button>
      </div>
    </div>
  );
}
