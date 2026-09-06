import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Globe2, ShieldAlert, BellRing, Search, Radar, ShieldHalf, RefreshCw } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { KpiCard } from "@/components/dashboard/KpiCard";
import { AttackSurfaceOverview } from "@/components/dashboard/AttackSurfaceOverview";
import { RecentFindingsList } from "@/components/dashboard/RecentFindingsList";
import { RecentAlertsList } from "@/components/dashboard/RecentAlertsList";
import { ActivityFeed } from "@/components/dashboard/ActivityFeed";
import { SeverityDistributionChart } from "@/components/charts/SeverityDistributionChart";
import { useOverview, useRiskAnalytics, useSecurityPosture } from "@/hooks/useAnalytics";
import { useStartScan } from "@/hooks/useScans";
import { useTargets } from "@/hooks/useWorkspace";
import { useWorkspaceStore } from "@/store/workspace";
import { useQueryClient } from "@tanstack/react-query";

export default function Dashboard() {
  const { data: overview, isLoading } = useOverview();
  const { data: risk } = useRiskAnalytics();
  const { data: posture } = useSecurityPosture();
  const { data: targets } = useTargets();
  const currentTargetId = useWorkspaceStore((s) => s.currentTargetId);
  const currentTarget = targets?.find((t) => t.id === currentTargetId);
  const startScan = useStartScan();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [refreshing, setRefreshing] = useState(false);

  async function handleRefresh() {
    setRefreshing(true);
    await queryClient.invalidateQueries();
    setRefreshing(false);
  }

  return (
    <div>
      <PageHeader
        title="Dashboard"
        description={currentTarget ? `${currentTarget.name} — ${currentTarget.value}` : "Loading target..."}
        actions={
          <>
            <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
              <RefreshCw className={refreshing ? "size-3.5 animate-spin" : "size-3.5"} /> Refresh
            </Button>
            <Button
              size="sm"
              onClick={() => currentTarget && startScan.mutate({ targetValue: currentTarget.value, scanType: "http" })}
              disabled={!currentTarget || startScan.isPending}
            >
              <Radar className="size-3.5" /> Start Scan
            </Button>
          </>
        }
      />

      <div className="space-y-4 p-6">
        {posture && (
          <div className="flex items-center gap-4 rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-4 py-3">
            <ShieldHalf className="size-5 text-[color:var(--color-accent)]" />
            <div>
              <p className="text-xs font-medium text-[color:var(--color-text-muted)]">Security posture</p>
              <p className="font-technical text-xl font-bold text-[color:var(--color-text)]">
                {posture.score}
                <span className="text-sm font-normal text-[color:var(--color-text-faint)]">/100</span>
              </p>
            </div>
            <p className="ml-2 max-w-md text-xs text-[color:var(--color-text-faint)]">
              Derived from {posture.scoredEntities} scored entities (100 − average risk score). Not an independent score
              — see docs/analytics/metrics.md.
            </p>
          </div>
        )}

        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <KpiCard label="Total Assets" value={overview?.totalAssets ?? 0} icon={Globe2} href="/assets" isLoading={isLoading} />
          <KpiCard label="Monitored Assets" value={overview?.monitoredAssets ?? 0} icon={Globe2} href="/assets" isLoading={isLoading} />
          <KpiCard
            label="Critical Risk Assets"
            value={overview?.criticalRiskAssets ?? 0}
            icon={Globe2}
            href="/risk"
            tone={overview && overview.criticalRiskAssets > 0 ? "danger" : "neutral"}
            isLoading={isLoading}
          />
          <KpiCard
            label="Open Findings"
            value={overview?.openFindings ?? 0}
            icon={ShieldAlert}
            href="/findings?status=open"
            tone={overview && overview.openFindings > 0 ? "warning" : "neutral"}
            isLoading={isLoading}
          />
          <KpiCard
            label="Open Alerts"
            value={overview?.openAlerts ?? 0}
            icon={BellRing}
            href="/alerts?status=open"
            tone={overview && overview.openAlerts > 0 ? "warning" : "neutral"}
            isLoading={isLoading}
          />
          <KpiCard
            label="Active Investigations"
            value={overview?.activeInvestigations ?? 0}
            icon={Search}
            href="/investigations"
            isLoading={isLoading}
          />
          <KpiCard label="Open Correlations" value={overview?.openCorrelations ?? 0} icon={Radar} href="/attack-chains" isLoading={isLoading} />
          <KpiCard label="Intelligence Records" value={overview?.intelligenceRecords ?? 0} icon={Globe2} href="/intelligence" isLoading={isLoading} />
        </div>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1.4fr_1fr]">
          <Card>
            <CardHeader>
              <CardTitle>Attack Surface Overview</CardTitle>
              <span className="text-xs text-[color:var(--color-text-faint)]">Click a node to view assets</span>
            </CardHeader>
            <AttackSurfaceOverview />
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Risk Overview</CardTitle>
            </CardHeader>
            <div className="p-4">
              <SeverityDistributionChart data={risk?.distribution ?? []} />
            </div>
          </Card>
        </div>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Recent Findings</CardTitle>
              <Button variant="ghost" size="sm" onClick={() => navigate("/findings")}>
                View all
              </Button>
            </CardHeader>
            <RecentFindingsList />
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Recent Alerts</CardTitle>
              <Button variant="ghost" size="sm" onClick={() => navigate("/alerts")}>
                View all
              </Button>
            </CardHeader>
            <RecentAlertsList />
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Activity</CardTitle>
            <Button variant="ghost" size="sm" onClick={() => navigate("/timeline")}>
              View timeline
            </Button>
          </CardHeader>
          <ActivityFeed />
        </Card>
      </div>
    </div>
  );
}
