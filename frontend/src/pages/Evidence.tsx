import { FileCheck2, ShieldCheck } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { EmptyState } from "@/components/common/EmptyState";
import { Card, CardContent } from "@/components/ui/Card";
import { CardSkeleton } from "@/components/ui/Skeleton";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/Tabs";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/Table";
import { Badge } from "@/components/ui/Badge";
import { useEvidencePackages, useControlEvidence } from "@/hooks/useReports";
import { formatTimestamp, truncateId } from "@/lib/utils";

export default function Evidence() {
  const { data: packages, isLoading: packagesLoading } = useEvidencePackages();
  const { data: controls, isLoading: controlsLoading } = useControlEvidence();

  return (
    <div>
      <PageHeader title="Evidence" description="Hashed evidence packages and control-evidence records — integrity information only, never an authentication mechanism." />

      <div className="p-6">
        <Tabs defaultValue="packages">
          <TabsList>
            <TabsTrigger value="packages">Evidence Packages</TabsTrigger>
            <TabsTrigger value="controls">Control Evidence</TabsTrigger>
          </TabsList>

          <TabsContent value="packages">
            {packagesLoading ? (
              <CardSkeleton />
            ) : !packages || packages.length === 0 ? (
              <EmptyState icon={FileCheck2} title="No evidence packages" description="Create one from an approved report via the CLI (ai-recon evidence-package create)." />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Report</TableHead>
                    <TableHead>Items</TableHead>
                    <TableHead>Manifest hash</TableHead>
                    <TableHead>Created by</TableHead>
                    <TableHead>Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {packages.map((p) => (
                    <TableRow key={p.id}>
                      <TableCell>{p.reportTitle}</TableCell>
                      <TableCell className="font-technical">{p.itemCount}</TableCell>
                      <TableCell className="font-technical text-xs text-[color:var(--color-text-muted)]" title={p.manifestHash}>
                        {truncateId(p.manifestHash, 14, 6)}
                      </TableCell>
                      <TableCell className="text-[color:var(--color-text-muted)]">{p.createdBy}</TableCell>
                      <TableCell className="text-[color:var(--color-text-muted)]">{formatTimestamp(p.createdAt)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </TabsContent>

          <TabsContent value="controls">
            {controlsLoading ? (
              <CardSkeleton />
            ) : !controls || controls.length === 0 ? (
              <EmptyState icon={ShieldCheck} title="No control evidence recorded" description="This is a generic, framework-agnostic evidence ledger — record evidence via the CLI (ai-recon control record)." />
            ) : (
              <Card>
                <CardContent className="space-y-2 p-3">
                  {controls.map((c) => (
                    <div key={c.id} className="flex items-center justify-between rounded-md border border-[color:var(--color-border)] px-3 py-2">
                      <div>
                        <Badge variant="outline">{c.controlId}</Badge>
                        <p className="mt-1 text-xs text-[color:var(--color-text-muted)]">{c.description}</p>
                      </div>
                      <span className="text-xs text-[color:var(--color-text-faint)]">{formatTimestamp(c.collectedAt)}</span>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
