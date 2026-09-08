import { useState } from "react";
import { ScrollText, Search } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { EmptyState } from "@/components/common/EmptyState";
import { ErrorState } from "@/components/common/ErrorState";
import { Pagination } from "@/components/common/Pagination";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/Table";
import { TableSkeleton } from "@/components/ui/Skeleton";
import { Input } from "@/components/ui/Input";
import { useAuditEvents } from "@/hooks/useAudit";
import { useCursorPagination } from "@/hooks/useCursorPagination";
import { useTargets } from "@/hooks/useWorkspace";
import { useWorkspaceStore } from "@/store/workspace";
import { formatTimestamp } from "@/lib/utils";

/**
 * This backend has no separate audit-log table — the investigation
 * timeline IS its audit trail (see src/api/audit.ts's header comment,
 * mirroring docs/reporting/reports.md's own "Audit report" precedent).
 */
export default function AuditLog() {
  const pagination = useCursorPagination(30);
  const [search, setSearch] = useState("");
  const { data, isLoading, isError, error, refetch } = useAuditEvents(pagination.pageParams);
  const { data: targets } = useTargets();
  const currentTargetId = useWorkspaceStore((s) => s.currentTargetId);
  const projectName = targets?.find((t) => t.id === currentTargetId)?.name ?? "—";

  const items = (data?.items ?? []).filter(
    (e) => !search || e.title.toLowerCase().includes(search.toLowerCase()) || e.actor.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <div>
      <PageHeader title="Audit Log" description="Every recorded investigation-timeline event for this target, in one searchable log." />

      <div className="flex items-center gap-2 border-b border-[color:var(--color-border)] px-6 py-3">
        <div className="relative w-72">
          <Search className="absolute left-2.5 top-2.5 size-3.5 text-[color:var(--color-text-faint)]" />
          <Input placeholder="Search by actor or action..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-8" />
        </div>
      </div>

      {isError && <ErrorState error={error} onRetry={refetch} />}
      {!isError && isLoading && <TableSkeleton />}
      {!isError && !isLoading && items.length === 0 && (
        <EmptyState icon={ScrollText} title="No audit events" description="Events are recorded as investigations progress — see the Timeline page for the same data in a chronological view." />
      )}
      {!isError && !isLoading && items.length > 0 && (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Timestamp</TableHead>
                <TableHead>Actor</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Resource</TableHead>
                <TableHead>Project</TableHead>
                <TableHead>Result</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((event) => (
                <TableRow key={event.id}>
                  <TableCell className="font-technical text-xs text-[color:var(--color-text-muted)]">{formatTimestamp(event.timestamp)}</TableCell>
                  <TableCell>{event.actor}</TableCell>
                  <TableCell>{event.type.replace(/_/g, " ")}</TableCell>
                  <TableCell className="font-technical text-xs text-[color:var(--color-text-muted)]">
                    {event.sourceType}
                    {event.sourceId ? `:${event.sourceId.slice(0, 8)}` : ""}
                  </TableCell>
                  <TableCell className="text-[color:var(--color-text-muted)]">{projectName}</TableCell>
                  <TableCell className="max-w-xs truncate text-[color:var(--color-text-muted)]">{event.description}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
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
  );
}
