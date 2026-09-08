import { Gauge } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { EmptyState } from "@/components/common/EmptyState";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { Skeleton } from "@/components/ui/Skeleton";
import { SeverityDistributionChart } from "@/components/charts/SeverityDistributionChart";
import { TrendChart } from "@/components/charts/TrendChart";
import { useRiskAnalytics, useSecurityPosture } from "@/hooks/useAnalytics";
import { useRiskScores } from "@/hooks/useIntelligence";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/Table";
import { SeverityBadge } from "@/components/ui/Badge";
import { formatRelativeTime } from "@/lib/utils";

export default function Risk() {
  const { data: risk, isLoading } = useRiskAnalytics();
  const { data: posture } = useSecurityPosture();
  const { data: assetRisk } = useRiskScores("asset");

  const topRisk = [...(assetRisk ?? [])].sort((a, b) => b.score - a.score).slice(0, 10);

  return (
    <div>
      <PageHeader title="Risk" description="Risk scoring is a documented derivation from finding severity, exposure, and intelligence context — never a raw probability." />

      <div className="space-y-4 p-6">
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <Card>
            <CardHeader>
              <CardTitle>Security posture</CardTitle>
            </CardHeader>
            <CardContent>
              {posture ? (
                <>
                  <p className="font-technical text-4xl font-bold text-[color:var(--color-text)]">{posture.score}<span className="text-base font-normal text-[color:var(--color-text-faint)]">/100</span></p>
                  <p className="mt-1 text-xs text-[color:var(--color-text-muted)]">
                    100 − average risk score across {posture.scoredEntities} scored entities.
                  </p>
                </>
              ) : (
                <Skeleton className="h-10 w-24" />
              )}
            </CardContent>
          </Card>
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle>Risk distribution</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? <Skeleton className="h-40" /> : <SeverityDistributionChart data={risk?.distribution ?? []} />}
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Risk trend</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-56" />
            ) : (
              <TrendChart
                data={(risk?.trend ?? []).map((b) => ({ bucketStart: b.bucketStart, count: b.averageScore }))}
                label="Average score"
                color="var(--color-warning)"
              />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Highest-risk assets</CardTitle>
          </CardHeader>
          {topRisk.length === 0 ? (
            <EmptyState icon={Gauge} title="No scored assets" description="Risk scores are calculated once findings and intelligence context exist for an asset." />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Asset</TableHead>
                  <TableHead>Score</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Calculated</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {topRisk.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell className="font-technical">{r.entityId}</TableCell>
                    <TableCell className="font-technical font-semibold">{r.score}</TableCell>
                    <TableCell>
                      <SeverityBadge severity={r.severity} />
                    </TableCell>
                    <TableCell className="text-[color:var(--color-text-muted)]">{formatRelativeTime(r.calculatedAt)}</TableCell>
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
