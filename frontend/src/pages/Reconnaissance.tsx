import { useState } from "react";
import { Radar } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Label } from "@/components/ui/Input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/Select";
import { StatusBadge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/common/EmptyState";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/Table";
import { TableSkeleton } from "@/components/ui/Skeleton";
import { useTargets } from "@/hooks/useWorkspace";
import { useWorkspaceStore } from "@/store/workspace";
import { useScans, useStartScan } from "@/hooks/useScans";
import type { ScanType } from "@/types/scan";
import { formatRelativeTime, formatTimestamp } from "@/lib/utils";

const SCAN_TYPES: { value: ScanType; label: string; description: string }[] = [
  { value: "http", label: "HTTP Discovery", description: "Probe known HTTP(S)/API/AI-service candidate paths." },
  { value: "network", label: "Network Discovery", description: "TCP connect scan across a HOST/IP/CIDR target." },
  { value: "dns", label: "DNS Discovery", description: "Forward DNS records + reverse PTR lookups." },
  { value: "subdomain", label: "Subdomain Enumeration", description: "Wordlist-based subdomain discovery." },
  { value: "endpoint", label: "Endpoint & API Discovery", description: "Bounded crawl for endpoints, robots.txt, sitemap, OpenAPI." },
  { value: "fingerprint", label: "Fingerprinting", description: "Passive technology identification from already-collected evidence." },
];

export default function Reconnaissance() {
  const { data: targets } = useTargets();
  const currentTargetId = useWorkspaceStore((s) => s.currentTargetId);
  const currentTarget = targets?.find((t) => t.id === currentTargetId);
  const [scanType, setScanType] = useState<ScanType>("http");
  const startScan = useStartScan();
  const { data: scans, isLoading } = useScans({ limit: 8 });

  return (
    <div>
      <PageHeader title="Reconnaissance" description="Run a discovery operation and watch newly discovered assets appear." />

      <div className="grid grid-cols-1 gap-4 p-6 lg:grid-cols-[1fr_1.4fr]">
        <Card>
          <CardHeader>
            <CardTitle>Start a scan</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-1.5">
              <Label>Target</Label>
              <div className="rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-surface-elevated)] px-3 py-2 font-technical text-sm text-[color:var(--color-text)]">
                {currentTarget?.value ?? "No target selected"}
              </div>
            </div>
            <div className="space-y-1.5">
              <Label>Operation</Label>
              <Select value={scanType} onValueChange={(v) => setScanType(v as ScanType)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SCAN_TYPES.map((s) => (
                    <SelectItem key={s.value} value={s.value}>
                      {s.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-[color:var(--color-text-faint)]">
                {SCAN_TYPES.find((s) => s.value === scanType)?.description}
              </p>
            </div>
            <Button
              className="w-full"
              onClick={() => currentTarget && startScan.mutate({ targetValue: currentTarget.value, scanType })}
              disabled={!currentTarget || startScan.isPending}
            >
              <Radar className="size-3.5" /> {startScan.isPending ? "Starting..." : "Start Scan"}
            </Button>
            <p className="text-xs leading-relaxed text-[color:var(--color-text-faint)]">
              This backend runs discovery commands synchronously to completion — the "running" status shown here
              anticipates a future async execution model; see docs/architecture/overview.md.
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recent scans</CardTitle>
          </CardHeader>
          {isLoading && <TableSkeleton rows={4} cols={4} />}
          {!isLoading && (!scans || scans.items.length === 0) && (
            <EmptyState icon={Radar} title="No scans yet" description="Start your first scan above to begin discovering assets." />
          )}
          {!isLoading && scans && scans.items.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Type</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Started</TableHead>
                  <TableHead>Duration</TableHead>
                  <TableHead>Assets</TableHead>
                  <TableHead>Findings</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.items.map((scan) => (
                  <TableRow key={scan.id}>
                    <TableCell>{scan.scanType}</TableCell>
                    <TableCell>
                      <StatusBadge status={scan.status} />
                    </TableCell>
                    <TableCell className="text-[color:var(--color-text-muted)]" title={formatTimestamp(scan.startedAt)}>
                      {formatRelativeTime(scan.startedAt)}
                    </TableCell>
                    <TableCell className="font-technical">{scan.durationMs ? `${Math.round(scan.durationMs / 1000)}s` : "—"}</TableCell>
                    <TableCell className="font-technical">{scan.assetsDiscovered}</TableCell>
                    <TableCell className="font-technical">{scan.findingsDiscovered}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Card>
      </div>
    </div>
  );
}
