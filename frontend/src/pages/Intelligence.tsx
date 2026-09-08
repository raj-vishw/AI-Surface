import { useState } from "react";
import { ScanSearch, ShieldAlert } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { EmptyState } from "@/components/common/EmptyState";
import { ErrorState } from "@/components/common/ErrorState";
import { Pagination } from "@/components/common/Pagination";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/Table";
import { TableSkeleton } from "@/components/ui/Skeleton";
import { Badge } from "@/components/ui/Badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/Select";
import { useIntelligence } from "@/hooks/useIntelligence";
import { useCursorPagination } from "@/hooks/useCursorPagination";
import type { IndicatorType } from "@/types/intelligence";
import { formatRelativeTime } from "@/lib/utils";

const INDICATOR_TYPES: IndicatorType[] = ["domain", "subdomain", "ipv4", "ipv6", "url", "hostname", "certificate", "technology", "hash"];

export default function Intelligence() {
  const pagination = useCursorPagination(20);
  const [indicatorType, setIndicatorType] = useState<IndicatorType | "all">("all");
  const { data, isLoading, isError, error, refetch } = useIntelligence(
    { indicatorType: indicatorType === "all" ? undefined : indicatorType },
    pagination.pageParams,
  );

  return (
    <div>
      <PageHeader title="Threat Intelligence" description="Enrichment records for indicators observed across this target's assets." />

      <div className="flex items-center gap-2 border-b border-[color:var(--color-border)] px-6 py-3">
        <Select value={indicatorType} onValueChange={(v) => setIndicatorType(v as IndicatorType | "all")}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Indicator type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All indicator types</SelectItem>
            {INDICATOR_TYPES.map((t) => (
              <SelectItem key={t} value={t}>{t}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {isError && <ErrorState error={error} onRetry={refetch} />}
      {!isError && isLoading && <TableSkeleton />}
      {!isError && !isLoading && data && data.items.length === 0 && (
        <EmptyState icon={ScanSearch} title="No intelligence records" description="Records appear once enrichment providers evaluate indicators observed for this target." />
      )}
      {!isError && !isLoading && data && data.items.length > 0 && (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Indicator</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Provider</TableHead>
                <TableHead>Confidence</TableHead>
                <TableHead>Reputation</TableHead>
                <TableHead>Observed</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.map((r) => (
                <TableRow key={r.id}>
                  <TableCell className="max-w-xs truncate font-technical">{r.indicatorValue}</TableCell>
                  <TableCell>{r.indicatorType}</TableCell>
                  <TableCell className="text-[color:var(--color-text-muted)]">{r.providerId}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{r.confidence}</Badge>
                  </TableCell>
                  <TableCell>
                    {r.malicious ? (
                      <span className="flex items-center gap-1 text-xs font-medium text-[color:var(--color-danger)]">
                        <ShieldAlert className="size-3" /> Malicious
                      </span>
                    ) : r.suspicious ? (
                      <span className="text-xs font-medium text-[color:var(--color-warning)]">Suspicious</span>
                    ) : (
                      <span className="text-xs text-[color:var(--color-text-faint)]">Clean</span>
                    )}
                  </TableCell>
                  <TableCell className="text-[color:var(--color-text-muted)]">{formatRelativeTime(r.observedAt)}</TableCell>
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
