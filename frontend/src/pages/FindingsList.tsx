import { useNavigate, useSearchParams } from "react-router-dom";
import { ShieldAlert, Search } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { EmptyState } from "@/components/common/EmptyState";
import { ErrorState } from "@/components/common/ErrorState";
import { Pagination } from "@/components/common/Pagination";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/Table";
import { TableSkeleton } from "@/components/ui/Skeleton";
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { Input } from "@/components/ui/Input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/Select";
import { useFindings } from "@/hooks/useFindings";
import { useCursorPagination } from "@/hooks/useCursorPagination";
import type { Severity } from "@/lib/severity";
import type { FindingCategory, FindingStatus } from "@/types/finding";
import { debounce, formatRelativeTime } from "@/lib/utils";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];
const STATUSES: FindingStatus[] = ["open", "resolved", "reopened", "accepted_risk", "false_positive"];

export default function FindingsList() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const pagination = useCursorPagination(20);

  const severity = (params.get("severity") as Severity) || undefined;
  const status = (params.get("status") as FindingStatus) || undefined;
  const category = (params.get("category") as FindingCategory) || undefined;

  const { data, isLoading, isError, error, refetch } = useFindings(
    { severity, status, category, search: params.get("search") ?? undefined },
    pagination.pageParams,
  );

  const setParam = (key: string, value: string) => {
    setParams((p) => {
      if (value === "all" || !value) p.delete(key);
      else p.set(key, value);
      return p;
    });
    pagination.reset();
  };

  const debouncedSearch = debounce((v: string) => setParam("search", v), 300);

  return (
    <div>
      <PageHeader title="Findings" description="Normalized, evidence-backed security findings across every asset for this target." />

      <div className="flex flex-wrap items-center gap-2 border-b border-[color:var(--color-border)] px-6 py-3">
        <div className="relative w-64">
          <Search className="absolute left-2.5 top-2.5 size-3.5 text-[color:var(--color-text-faint)]" />
          <Input
            placeholder="Search findings..."
            defaultValue={params.get("search") ?? ""}
            onChange={(e) => debouncedSearch(e.target.value)}
            className="pl-8"
          />
        </div>
        <Select value={severity ?? "all"} onValueChange={(v) => setParam("severity", v)}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            {SEVERITIES.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
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
              <SelectItem key={s} value={s}>
                {s.replace(/_/g, " ")}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {isError && <ErrorState error={error} onRetry={refetch} />}
      {!isError && isLoading && <TableSkeleton />}
      {!isError && !isLoading && data && data.items.length === 0 && (
        <EmptyState icon={ShieldAlert} title="No findings match these filters" description="Try clearing a filter, or run a detection scan for this target." />
      )}
      {!isError && !isLoading && data && data.items.length > 0 && (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Severity</TableHead>
                <TableHead>Title</TableHead>
                <TableHead>Asset</TableHead>
                <TableHead>Category</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>First Seen</TableHead>
                <TableHead>Last Seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.map((f) => (
                <TableRow key={f.id} className="cursor-pointer" onClick={() => navigate(`/findings/${f.id}`)}>
                  <TableCell>
                    <SeverityBadge severity={f.severity} />
                  </TableCell>
                  <TableCell className="max-w-sm truncate">{f.title}</TableCell>
                  <TableCell className="font-technical text-[color:var(--color-text-muted)]">{f.assetName ?? f.assetId}</TableCell>
                  <TableCell>{f.category.replace(/_/g, " ")}</TableCell>
                  <TableCell>
                    <StatusBadge status={f.status} />
                  </TableCell>
                  <TableCell className="text-[color:var(--color-text-muted)]">{formatRelativeTime(f.firstSeen)}</TableCell>
                  <TableCell className="text-[color:var(--color-text-muted)]">{formatRelativeTime(f.lastSeen)}</TableCell>
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
