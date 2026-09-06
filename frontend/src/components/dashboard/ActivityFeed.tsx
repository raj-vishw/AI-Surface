import { Link } from "react-router-dom";
import { History } from "lucide-react";
import { useAuditEvents } from "@/hooks/useAudit";
import { Skeleton } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/common/EmptyState";
import { formatRelativeTime } from "@/lib/utils";
import { cn } from "@/lib/utils";
import { SEVERITY_STYLES, normalizeSeverity } from "@/lib/severity";

export function ActivityFeed() {
  const { data, isLoading } = useAuditEvents({ limit: 10 });

  if (isLoading) {
    return (
      <div className="space-y-3 p-4">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-8" />
        ))}
      </div>
    );
  }

  if (!data || data.items.length === 0) {
    return <EmptyState icon={History} title="No recent activity" description="Activity will appear here once investigations start recording timeline events." />;
  }

  return (
    <ul className="divide-y divide-[color:var(--color-border)]">
      {data.items.map((event) => {
        const style = SEVERITY_STYLES[normalizeSeverity(event.severity)];
        return (
          <li key={event.id}>
            <Link
              to={`/investigations/${event.investigationId}`}
              className="flex items-start gap-3 px-4 py-2.5 hover:bg-[color:var(--color-surface-hover)]"
            >
              <span className={cn("mt-1.5 size-1.5 shrink-0 rounded-full", style.bg)} style={{ backgroundColor: style.raw }} />
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm text-[color:var(--color-text)]">{event.title}</p>
                <p className="truncate text-xs text-[color:var(--color-text-faint)]">
                  {event.actor} · {event.type.replace(/_/g, " ")}
                </p>
              </div>
              <span className="shrink-0 text-xs text-[color:var(--color-text-faint)]">{formatRelativeTime(event.timestamp)}</span>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}
