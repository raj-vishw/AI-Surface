import { Link } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import { useFindings } from "@/hooks/useFindings";
import { SeverityBadge } from "@/components/ui/Badge";
import { Skeleton } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/common/EmptyState";
import { formatRelativeTime } from "@/lib/utils";

export function RecentFindingsList() {
  const { data, isLoading } = useFindings({ status: "open" }, { limit: 6 });

  if (isLoading) {
    return (
      <div className="space-y-2 p-4">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-10" />
        ))}
      </div>
    );
  }

  if (!data || data.items.length === 0) {
    return (
      <EmptyState
        icon={ShieldAlert}
        title="No open findings"
        description="Every known finding for this target is currently resolved or suppressed."
      />
    );
  }

  return (
    <ul className="divide-y divide-[color:var(--color-border)]">
      {data.items.map((f) => (
        <li key={f.id}>
          <Link to={`/findings/${f.id}`} className="flex items-center gap-3 px-4 py-2.5 hover:bg-[color:var(--color-surface-hover)]">
            <SeverityBadge severity={f.severity} />
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm text-[color:var(--color-text)]">{f.title}</p>
              <p className="truncate font-technical text-xs text-[color:var(--color-text-faint)]">{f.assetName ?? f.assetId}</p>
            </div>
            <span className="shrink-0 text-xs text-[color:var(--color-text-faint)]">{formatRelativeTime(f.lastSeen)}</span>
          </Link>
        </li>
      ))}
    </ul>
  );
}
