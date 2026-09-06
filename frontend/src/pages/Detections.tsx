import { Siren } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { EmptyState } from "@/components/common/EmptyState";
import { Card } from "@/components/ui/Card";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/Table";
import { TableSkeleton } from "@/components/ui/Skeleton";
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/Tabs";
import { useRules, useDetectionMatches } from "@/hooks/useDetections";
import { formatRelativeTime, formatTimestamp } from "@/lib/utils";

export default function Detections() {
  const { data: rules, isLoading: rulesLoading } = useRules();
  const { data: matches, isLoading: matchesLoading } = useDetectionMatches({ limit: 25 });

  return (
    <div>
      <PageHeader title="Detections" description="Detection rules and the matches they've produced (Phase 11's rule engine)." />

      <div className="p-6">
        <Tabs defaultValue="rules">
          <TabsList>
            <TabsTrigger value="rules">Rules {rules ? `(${rules.length})` : ""}</TabsTrigger>
            <TabsTrigger value="matches">Matches {matches ? `(${matches.total})` : ""}</TabsTrigger>
          </TabsList>

          <TabsContent value="rules">
            <Card>
              {rulesLoading ? (
                <TableSkeleton />
              ) : !rules || rules.length === 0 ? (
                <EmptyState icon={Siren} title="No rules configured" description="Install a built-in rule or author a custom one via the CLI to begin detecting matches." />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Version</TableHead>
                      <TableHead>Updated</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rules.map((r) => (
                      <TableRow key={r.id}>
                        <TableCell>
                          <p className="font-medium">{r.name}</p>
                          <p className="text-xs text-[color:var(--color-text-faint)]">{r.description}</p>
                        </TableCell>
                        <TableCell>{r.ruleType}</TableCell>
                        <TableCell><SeverityBadge severity={r.severity} /></TableCell>
                        <TableCell><StatusBadge status={r.status} /></TableCell>
                        <TableCell className="font-technical">v{r.version}</TableCell>
                        <TableCell className="text-[color:var(--color-text-muted)]">{formatRelativeTime(r.updatedAt)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </Card>
          </TabsContent>

          <TabsContent value="matches">
            <Card>
              {matchesLoading ? (
                <TableSkeleton />
              ) : !matches || matches.items.length === 0 ? (
                <EmptyState icon={Siren} title="No detection matches" description="Matches appear here once a rule evaluates against new observations." />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Rule</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>First Observed</TableHead>
                      <TableHead>Last Observed</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {matches.items.map((m) => (
                      <TableRow key={m.id}>
                        <TableCell>{m.ruleName}</TableCell>
                        <TableCell><StatusBadge status={m.status} /></TableCell>
                        <TableCell className="text-[color:var(--color-text-muted)]" title={formatTimestamp(m.firstObservedAt)}>
                          {formatRelativeTime(m.firstObservedAt)}
                        </TableCell>
                        <TableCell className="text-[color:var(--color-text-muted)]" title={formatTimestamp(m.lastObservedAt)}>
                          {formatRelativeTime(m.lastObservedAt)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
