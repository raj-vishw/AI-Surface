import { Link } from "react-router-dom";
import { BellRing } from "lucide-react";
import { useAlerts } from "@/hooks/useAlerts";
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { Skeleton } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/common/EmptyState";
import { formatRelativeTime } from "@/lib/utils";

export function RecentAlertsList() {
  const { data, isLoading } = useAlerts({}, { limit: 6 });

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
    return <EmptyState icon={BellRing} title="No alerts" description="No detection alerts have fired for this target yet." />;
  }

  return (
    <ul className="divide-y divide-[color:var(--color-border)]">
      {data.items.map((a) => (
        <li key={a.id}>
          <Link to="/alerts" className="flex items-center gap-3 px-4 py-2.5 hover:bg-[color:var(--color-surface-hover)]">
            <SeverityBadge severity={a.severity} />
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm text-[color:var(--color-text)]">{a.title}</p>
              <p className="truncate text-xs text-[color:var(--color-text-faint)]">{a.ruleName}</p>
            </div>
            <StatusBadge status={a.status} className="shrink-0" />
            <span className="hidden shrink-0 text-xs text-[color:var(--color-text-faint)] sm:inline">{formatRelativeTime(a.lastObservedAt)}</span>
          </Link>
        </li>
      ))}
    </ul>
  );
}
