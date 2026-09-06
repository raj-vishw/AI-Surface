import { useState, type ReactNode } from "react";
import { PageHeader } from "@/components/common/PageHeader";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Skeleton } from "@/components/ui/Skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/Select";
import { TrendChart } from "@/components/charts/TrendChart";
import { NamedCountBarChart } from "@/components/charts/NamedCountBarChart";
import { SeverityDistributionChart } from "@/components/charts/SeverityDistributionChart";
import {
  useFindingAnalytics,
  useAlertAnalytics,
  useDetectionAnalytics,
  useInvestigationAnalytics,
  useCorrelationAnalytics,
  useIntelligenceAnalytics,
  useAIAnalytics,
  useAssetAnalytics,
} from "@/hooks/useAnalytics";
import type { RangePreset } from "@/types/analytics";

const RANGES: { value: RangePreset; label: string }[] = [
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "90d", label: "Last 90 days" },
];

export default function Analytics() {
  const [range, setRange] = useState<RangePreset>("30d");

  const findings = useFindingAnalytics(range);
  const alerts = useAlertAnalytics(range);
  const detections = useDetectionAnalytics(range);
  const investigations = useInvestigationAnalytics(range);
  const correlations = useCorrelationAnalytics(range);
  const intelligence = useIntelligenceAnalytics();
  const ai = useAIAnalytics(range);
  const assets = useAssetAnalytics();

  return (
    <div>
      <PageHeader
        title="Analytics"
        description="Backend-computed aggregates over this target's own data — never fabricated numbers."
        actions={
          <Select value={range} onValueChange={(v) => setRange(v as RangePreset)}>
            <SelectTrigger className="w-44">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {RANGES.map((r) => (
                <SelectItem key={r.value} value={r.value}>{r.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        }
      />

      <div className="grid grid-cols-1 gap-4 p-6 lg:grid-cols-2">
        <ChartCard title="Findings over time">
          {findings.isLoading ? <Skeleton className="h-56" /> : <TrendChart data={findings.data?.overTime ?? []} label="Findings" />}
        </ChartCard>
        <ChartCard title="Findings by severity">
          {findings.isLoading ? <Skeleton className="h-48" /> : <SeverityDistributionChart data={findings.data?.bySeverity ?? []} />}
        </ChartCard>

        <ChartCard title="Alerts over time">
          {alerts.isLoading ? <Skeleton className="h-56" /> : <TrendChart data={alerts.data?.overTime ?? []} label="Alerts" color="var(--color-warning)" />}
        </ChartCard>
        <ChartCard title="Alerts by rule">
          {alerts.isLoading ? <Skeleton className="h-56" /> : <NamedCountBarChart data={alerts.data?.byRule ?? []} color="var(--color-warning)" />}
        </ChartCard>

        <ChartCard title="Detection volume">
          {detections.isLoading ? <Skeleton className="h-56" /> : <TrendChart data={detections.data?.matchesOverTime ?? []} label="Matches" color="var(--color-danger)" />}
        </ChartCard>
        <ChartCard title="Findings by category">
          {findings.isLoading ? <Skeleton className="h-56" /> : <NamedCountBarChart data={findings.data?.byCategory ?? []} />}
        </ChartCard>

        <ChartCard title="Investigation volume">
          {investigations.isLoading ? <Skeleton className="h-56" /> : <TrendChart data={investigations.data?.openedOverTime ?? []} label="Opened" color="var(--color-accent)" />}
        </ChartCard>
        <ChartCard title="Investigations by status">
          {investigations.isLoading ? <Skeleton className="h-56" /> : <NamedCountBarChart data={investigations.data?.byStatus ?? []} color="var(--color-accent)" />}
        </ChartCard>

        <ChartCard title="Correlations over time">
          {correlations.isLoading ? <Skeleton className="h-56" /> : <TrendChart data={correlations.data?.overTime ?? []} label="Correlations" color="var(--color-info)" />}
        </ChartCard>
        <ChartCard title="Attack-surface (asset types)">
          {assets.isLoading ? <Skeleton className="h-56" /> : <NamedCountBarChart data={assets.data?.byType ?? []} color="var(--color-info)" />}
        </ChartCard>

        <ChartCard title="Intelligence by indicator type">
          {intelligence.isLoading ? <Skeleton className="h-56" /> : <NamedCountBarChart data={intelligence.data?.byIndicatorType ?? []} color="var(--color-success)" />}
        </ChartCard>
        <ChartCard title="AI requests over time">
          {ai.isLoading ? <Skeleton className="h-56" /> : <TrendChart data={ai.data?.requestsOverTime ?? []} label="Requests" color="var(--color-accent)" />}
        </ChartCard>
      </div>

      {ai.data && (
        <div className="grid grid-cols-2 gap-4 px-6 pb-6 lg:grid-cols-4">
          <Stat label="Avg AI latency" value={`${ai.data.averageLatencyMs}ms`} />
          <Stat label="AI input tokens" value={ai.data.inputTokens.toLocaleString()} />
          <Stat label="AI output tokens" value={ai.data.outputTokens.toLocaleString()} />
          <Stat label="Mean investigation duration" value={`${Math.round((investigations.data?.meanDurationSeconds ?? 0) / 3600)}h`} />
        </div>
      )}
    </div>
  );
}

function ChartCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-3">
      <p className="text-xs text-[color:var(--color-text-faint)]">{label}</p>
      <p className="font-technical text-lg font-semibold text-[color:var(--color-text)]">{value}</p>
    </div>
  );
}
