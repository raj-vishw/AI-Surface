import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

/** A proper loading skeleton (spec §45 — never a bare "Loading..." text)
 * shaped to whatever content it stands in for via className. */
export function Skeleton({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("animate-pulse rounded-md bg-[color:var(--color-surface-hover)]", className)}
      {...props}
    />
  );
}

export function TableSkeleton({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="space-y-2 p-3">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex gap-3">
          {Array.from({ length: cols }).map((_, c) => (
            <Skeleton key={c} className="h-8 flex-1" />
          ))}
        </div>
      ))}
    </div>
  );
}

export function CardSkeleton({ className }: { className?: string }) {
  return (
    <div className={cn("space-y-3 p-4", className)}>
      <Skeleton className="h-4 w-1/3" />
      <Skeleton className="h-7 w-1/2" />
      <Skeleton className="h-3 w-2/3" />
    </div>
  );
}
