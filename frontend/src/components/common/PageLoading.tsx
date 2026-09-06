import { Skeleton } from "@/components/ui/Skeleton";

export function PageLoading() {
  return (
    <div className="space-y-4 p-6">
      <Skeleton className="h-7 w-48" />
      <div className="grid grid-cols-4 gap-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
      <Skeleton className="h-64" />
    </div>
  );
}
