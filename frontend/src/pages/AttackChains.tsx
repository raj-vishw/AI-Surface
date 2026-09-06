import { useNavigate } from "react-router-dom";
import { Waypoints } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { EmptyState } from "@/components/common/EmptyState";
import { ErrorState } from "@/components/common/ErrorState";
import { Card, CardContent } from "@/components/ui/Card";
import { CardSkeleton } from "@/components/ui/Skeleton";
import { SeverityBadge, StatusBadge, Badge } from "@/components/ui/Badge";
import { useAttackChains } from "@/hooks/useCorrelations";
import { formatRelativeTime } from "@/lib/utils";

export default function AttackChains() {
  const { data: chains, isLoading, isError, error, refetch } = useAttackChains();
  const navigate = useNavigate();

  return (
    <div>
      <PageHeader
        title="Attack Chains"
        description="A narrative reconstruction from correlated evidence — never proof of a confirmed attack."
      />

      <div className="space-y-3 p-6">
        {isError && <ErrorState error={error} onRetry={refetch} />}
        {!isError && isLoading && (
          <>
            <CardSkeleton />
            <CardSkeleton />
          </>
        )}
        {!isError && !isLoading && (!chains || chains.length === 0) && (
          <EmptyState icon={Waypoints} title="No attack chains" description="Chains are built from confirmed correlations with multiple linked evidence stages." />
        )}
        {!isError &&
          chains?.map((chain) => (
            <Card key={chain.id} className="cursor-pointer hover:border-[color:var(--color-border-strong)]" onClick={() => navigate(`/attack-chains/${chain.id}`)}>
              <CardContent className="flex items-center justify-between gap-4">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-[color:var(--color-text)]">{chain.name}</p>
                  <p className="mt-0.5 truncate text-xs text-[color:var(--color-text-muted)]">{chain.description}</p>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <SeverityBadge severity={chain.severity} />
                  <StatusBadge status={chain.status} />
                  <Badge variant="outline">{chain.confidence} confidence</Badge>
                  <span className="text-xs text-[color:var(--color-text-faint)]">{formatRelativeTime(chain.updatedAt)}</span>
                </div>
              </CardContent>
            </Card>
          ))}
      </div>
    </div>
  );
}
