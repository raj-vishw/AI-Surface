import { PageHeader } from "@/components/common/PageHeader";
import { EmptyState } from "@/components/common/EmptyState";
import { ErrorState } from "@/components/common/ErrorState";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/Table";
import { TableSkeleton } from "@/components/ui/Skeleton";
import { Badge } from "@/components/ui/Badge";
import { Fingerprint } from "lucide-react";
import { useTechnologies } from "@/hooks/useFingerprints";
import { formatRelativeTime } from "@/lib/utils";

export default function Technologies() {
  const { data, isLoading, isError, error, refetch } = useTechnologies();

  return (
    <div>
      <PageHeader title="Technologies" description="Technology stack detected across every asset for this target, via passive fingerprinting." />

      {isError && <ErrorState error={error} onRetry={refetch} />}
      {!isError && isLoading && <TableSkeleton />}
      {!isError && !isLoading && (!data || data.length === 0) && (
        <EmptyState icon={Fingerprint} title="No technologies detected" description="Run a scan with fingerprinting enabled to populate this view." />
      )}
      {!isError && !isLoading && data && data.length > 0 && (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Technology</TableHead>
              <TableHead>Category</TableHead>
              <TableHead>Versions</TableHead>
              <TableHead>Affected assets</TableHead>
              <TableHead>Open critical/high findings</TableHead>
              <TableHead>First seen</TableHead>
              <TableHead>Last seen</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.map((tech) => (
              <TableRow key={tech.technology}>
                <TableCell className="font-medium">{tech.technology}</TableCell>
                <TableCell>{tech.category.replace(/_/g, " ")}</TableCell>
                <TableCell className="font-technical">{tech.versions.length ? tech.versions.join(", ") : "—"}</TableCell>
                <TableCell className="font-technical">{tech.affectedAssetCount}</TableCell>
                <TableCell>
                  {tech.criticalFindings > 0 ? (
                    <Badge className="border-[color:var(--color-danger)]/30 bg-[color:var(--color-danger-muted)] text-[color:var(--color-danger)]">
                      {tech.criticalFindings}
                    </Badge>
                  ) : (
                    <span className="text-[color:var(--color-text-faint)]">0</span>
                  )}
                </TableCell>
                <TableCell className="text-[color:var(--color-text-muted)]">{formatRelativeTime(tech.firstSeen)}</TableCell>
                <TableCell className="text-[color:var(--color-text-muted)]">{formatRelativeTime(tech.lastSeen)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}
