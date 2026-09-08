import { useNavigate, useSearchParams } from "react-router-dom";
import { Search } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { EmptyState } from "@/components/common/EmptyState";
import { ErrorState } from "@/components/common/ErrorState";
import { Pagination } from "@/components/common/Pagination";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/Table";
import { TableSkeleton } from "@/components/ui/Skeleton";
import { SeverityBadge, StatusBadge, Badge } from "@/components/ui/Badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/Select";
import { useInvestigations } from "@/hooks/useInvestigations";
import { useCursorPagination } from "@/hooks/useCursorPagination";
import type { InvestigationStatus } from "@/types/investigation";
import { formatRelativeTime } from "@/lib/utils";

const STATUSES: InvestigationStatus[] = ["new", "open", "investigating", "contained", "resolved", "closed"];

export default function InvestigationsList() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const pagination = useCursorPagination(20);
  const status = (params.get("status") as InvestigationStatus) || undefined;

  const { data, isLoading, isError, error, refetch } = useInvestigations({ status }, pagination.pageParams);

  return (
    <div>
      <PageHeader title="Investigations" description="Active, recently updated, and high-priority security investigations for this target." />

      <div className="flex flex-wrap items-center gap-2 border-b border-[color:var(--color-border)] px-6 py-3">
        <Select
          value={status ?? "all"}
          onValueChange={(v) => {
            setParams((p) => {
              if (v === "all") p.delete("status");
              else p.set("status", v);
              return p;
            });
            pagination.reset();
          }}
        >
          <SelectTrigger className="w-44">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            {STATUSES.map((s) => (
              <SelectItem key={s} value={s}>{s}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {isError && <ErrorState error={error} onRetry={refetch} />}
      {!isError && isLoading && <TableSkeleton />}
      {!isError && !isLoading && data && data.items.length === 0 && (
        <EmptyState icon={Search} title="No investigations" description="Open one from a finding, alert, or accepted incident cluster to begin." />
      )}
      {!isError && !isLoading && data && data.items.length > 0 && (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Title</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Priority</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Analyst</TableHead>
                <TableHead>Updated</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.map((inv) => (
                <TableRow key={inv.id} className="cursor-pointer" onClick={() => navigate(`/investigations/${inv.id}`)}>
                  <TableCell className="max-w-sm truncate font-medium">{inv.title}</TableCell>
                  <TableCell><SeverityBadge severity={inv.severity} /></TableCell>
                  <TableCell><Badge variant="outline">{inv.priority}</Badge></TableCell>
                  <TableCell><StatusBadge status={inv.status} /></TableCell>
                  <TableCell className="text-[color:var(--color-text-muted)]">{inv.assignedTo}</TableCell>
                  <TableCell className="text-[color:var(--color-text-muted)]">{formatRelativeTime(inv.updatedAt)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Pagination
            shown={data.items.length}
            hasMore={data.hasMore}
            hasPrev={pagination.hasPrev}
            onNext={() => pagination.next(data.nextCursor)}
            onPrev={pagination.prev}
          />
        </>
      )}
    </div>
  );
}
