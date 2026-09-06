import { useSearchParams } from "react-router-dom";
import { BellRing, Check, Eye, X } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { EmptyState } from "@/components/common/EmptyState";
import { ErrorState } from "@/components/common/ErrorState";
import { Pagination } from "@/components/common/Pagination";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/Table";
import { TableSkeleton } from "@/components/ui/Skeleton";
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/Select";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/Tooltip";
import { useAlerts, useAlertActions } from "@/hooks/useAlerts";
import { useCursorPagination } from "@/hooks/useCursorPagination";
import type { Severity } from "@/lib/severity";
import type { AlertStatus } from "@/types/detection";
import { formatRelativeTime } from "@/lib/utils";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];
const STATUSES: AlertStatus[] = ["open", "acknowledged", "investigating", "resolved", "suppressed"];

export default function Alerts() {
  const [params, setParams] = useSearchParams();
  const pagination = useCursorPagination(20);
  const severity = (params.get("severity") as Severity) || undefined;
  const status = (params.get("status") as AlertStatus) || undefined;

  const { data, isLoading, isError, error, refetch } = useAlerts({ severity, status }, pagination.pageParams);
  const actions = useAlertActions();

  const setParam = (key: string, value: string) => {
    setParams((p) => {
      if (value === "all") p.delete(key);
      else p.set(key, value);
      return p;
    });
    pagination.reset();
  };

  return (
    <div>
      <PageHeader title="Alerts" description="Analyst-facing notifications for detection matches (Phase 11's rule engine)." />

      <div className="flex flex-wrap items-center gap-2 border-b border-[color:var(--color-border)] px-6 py-3">
        <Select value={severity ?? "all"} onValueChange={(v) => setParam("severity", v)}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            {SEVERITIES.map((s) => (
              <SelectItem key={s} value={s}>{s}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={status ?? "all"} onValueChange={(v) => setParam("status", v)}>
          <SelectTrigger className="w-40">
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
        <EmptyState icon={BellRing} title="No alerts match these filters" description="Clear a filter, or wait for the detection engine to fire on new matches." />
      )}
      {!isError && !isLoading && data && data.items.length > 0 && (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Severity</TableHead>
                <TableHead>Title</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last Observed</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.map((alert) => (
                <TableRow key={alert.id}>
                  <TableCell><SeverityBadge severity={alert.severity} /></TableCell>
                  <TableCell className="max-w-sm truncate">{alert.title}</TableCell>
                  <TableCell className="text-[color:var(--color-text-muted)]">{alert.ruleName}</TableCell>
                  <TableCell><StatusBadge status={alert.status} /></TableCell>
                  <TableCell className="text-[color:var(--color-text-muted)]">{formatRelativeTime(alert.lastObservedAt)}</TableCell>
                  <TableCell>
                    <div className="flex justify-end gap-1">
                      <ActionButton icon={Check} label="Acknowledge" onClick={() => actions.acknowledge.mutate(alert.id)} disabled={alert.status !== "open"} />
                      <ActionButton icon={Eye} label="Investigate" onClick={() => actions.investigate.mutate(alert.id)} disabled={alert.status === "investigating" || alert.status === "resolved"} />
                      <ActionButton icon={X} label="Dismiss" onClick={() => actions.dismiss.mutate(alert.id)} disabled={alert.status === "resolved" || alert.status === "suppressed"} />
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Pagination
            total={data.total}
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

function ActionButton({ icon: Icon, label, onClick, disabled }: { icon: typeof Check; label: string; onClick: () => void; disabled?: boolean }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button variant="ghost" size="icon" onClick={onClick} disabled={disabled} aria-label={label}>
          <Icon className="size-3.5" />
        </Button>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
}
