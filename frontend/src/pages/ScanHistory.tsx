import { Link } from "react-router-dom";
import { History } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { EmptyState } from "@/components/common/EmptyState";
import { ErrorState } from "@/components/common/ErrorState";
import { Pagination } from "@/components/common/Pagination";
import { Button } from "@/components/ui/Button";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/Table";
import { TableSkeleton } from "@/components/ui/Skeleton";
import { StatusBadge } from "@/components/ui/Badge";
import { useScans } from "@/hooks/useScans";
import { useCursorPagination } from "@/hooks/useCursorPagination";
import { formatTimestamp } from "@/lib/utils";

export default function ScanHistory() {
  const pagination = useCursorPagination(25);
  const { data, isLoading, isError, error, refetch } = useScans(pagination.pageParams);

  return (
    <div>
      <PageHeader
        title="Scan History"
        description="Every reconnaissance operation run against this target."
        actions={
          <Button asChild size="sm">
            <Link to="/reconnaissance">Start a scan</Link>
          </Button>
        }
      />

      {isError && <ErrorState error={error} onRetry={refetch} />}
      {!isError && isLoading && <TableSkeleton />}
      {!isError && !isLoading && data && data.items.length === 0 && (
        <EmptyState icon={History} title="No scans yet" description="Start your first reconnaissance operation to populate this history." />
      )}
      {!isError && !isLoading && data && data.items.length > 0 && (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Type</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Started</TableHead>
                <TableHead>Completed</TableHead>
                <TableHead>Duration</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Assets discovered</TableHead>
                <TableHead>Findings discovered</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.map((scan) => (
                <TableRow key={scan.id}>
                  <TableCell>{scan.scanType}</TableCell>
                  <TableCell className="font-technical">{scan.targetValue}</TableCell>
                  <TableCell className="text-[color:var(--color-text-muted)]">{formatTimestamp(scan.startedAt)}</TableCell>
                  <TableCell className="text-[color:var(--color-text-muted)]">{scan.completedAt ? formatTimestamp(scan.completedAt) : "—"}</TableCell>
                  <TableCell className="font-technical">{scan.durationMs ? `${Math.round(scan.durationMs / 1000)}s` : "—"}</TableCell>
                  <TableCell>
                    <StatusBadge status={scan.status} />
                    {scan.error && <p className="mt-1 max-w-xs truncate text-xs text-[color:var(--color-danger)]">{scan.error}</p>}
                  </TableCell>
                  <TableCell className="font-technical">{scan.assetsDiscovered}</TableCell>
                  <TableCell className="font-technical">{scan.findingsDiscovered}</TableCell>
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
