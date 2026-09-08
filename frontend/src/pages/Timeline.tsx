import { useState } from "react";
import { Link } from "react-router-dom";
import { History } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { EmptyState } from "@/components/common/EmptyState";
import { ErrorState } from "@/components/common/ErrorState";
import { Pagination } from "@/components/common/Pagination";
import { Skeleton } from "@/components/ui/Skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/Select";
import { useAuditEvents } from "@/hooks/useAudit";
import { useCursorPagination } from "@/hooks/useCursorPagination";
import { SEVERITY_STYLES, normalizeSeverity, type Severity } from "@/lib/severity";
import { formatTimestamp } from "@/lib/utils";
import { cn } from "@/lib/utils";

export default function Timeline() {
  const pagination = useCursorPagination(30);
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const { data, isLoading, isError, error, refetch } = useAuditEvents(pagination.pageParams);

  const items = (data?.items ?? []).filter((e) => severityFilter === "all" || normalizeSeverity(e.severity) === severityFilter);

  return (
    <div>
      <PageHeader title="Timeline" description="A unified chronological view of every recorded event across every investigation for this target." />

      <div className="flex items-center gap-2 border-b border-[color:var(--color-border)] px-6 py-3">
        <Select value={severityFilter} onValueChange={(v) => setSeverityFilter(v as Severity | "all")}>
          <SelectTrigger className="w-44">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            {(["critical", "high", "medium", "low", "informational"] as Severity[]).map((s) => (
              <SelectItem key={s} value={s}>{s}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="p-6">
        {isError && <ErrorState error={error} onRetry={refetch} />}
        {!isError && isLoading && (
          <div className="space-y-3">
            {Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-10" />)}
          </div>
        )}
        {!isError && !isLoading && items.length === 0 && (
          <EmptyState icon={History} title="No events" description="Events will appear here as investigations record findings, evidence, and status changes." />
        )}
        {!isError && !isLoading && items.length > 0 && (
          <>
            <ol className="space-y-0 border-l border-[color:var(--color-border)] pl-4">
              {items.map((event) => {
                const style = SEVERITY_STYLES[normalizeSeverity(event.severity)];
                return (
                  <li key={event.id} className="relative pb-5">
                    <span className={cn("absolute -left-[21px] top-1 size-2.5 rounded-full border-2 border-[color:var(--color-bg)]")} style={{ backgroundColor: style.raw }} />
                    <Link to={`/investigations/${event.investigationId}`} className="text-sm text-[color:var(--color-text)] hover:text-[color:var(--color-accent)]">
                      {event.title}
                    </Link>
                    <p className="text-xs text-[color:var(--color-text-muted)]">{event.description}</p>
                    <p className="mt-0.5 text-[0.65rem] text-[color:var(--color-text-faint)]">
                      {event.actor} · {event.type.replace(/_/g, " ")} · {formatTimestamp(event.timestamp)}
                    </p>
                  </li>
                );
              })}
            </ol>
            {data && (
              <Pagination
                shown={data.items.length}
                hasMore={data.hasMore}
                hasPrev={pagination.hasPrev}
                onNext={() => pagination.next(data.nextCursor)}
                onPrev={pagination.prev}
              />
            )}
          </>
        )}
      </div>
    </div>
  );
}
