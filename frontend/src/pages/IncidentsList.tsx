import { Link } from "react-router-dom";
import { ShieldQuestion, ArrowRight } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { EmptyState } from "@/components/common/EmptyState";
import { Card, CardContent } from "@/components/ui/Card";
import { CardSkeleton } from "@/components/ui/Skeleton";
import { StatusBadge, Badge } from "@/components/ui/Badge";
import { useIncidentClusters } from "@/hooks/useIncidents";
import { formatRelativeTime } from "@/lib/utils";

export default function IncidentsList() {
  const { data: clusters, isLoading } = useIncidentClusters();

  return (
    <div>
      <PageHeader
        title="Incidents"
        description="Suggested and accepted incident clusters — an accepted cluster becomes an Investigation (this backend has no separate incident table)."
      />

      <div className="space-y-3 p-6">
        {isLoading && (
          <>
            <CardSkeleton />
            <CardSkeleton />
          </>
        )}
        {!isLoading && (!clusters || clusters.length === 0) && (
          <EmptyState icon={ShieldQuestion} title="No incident clusters" description="Clusters are suggested automatically from temporally/technically related open findings." />
        )}
        {!isLoading &&
          clusters?.map((c) => (
            <Card key={c.id}>
              <CardContent className="flex items-center justify-between gap-4">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-[color:var(--color-text)]">{c.title}</p>
                  <p className="mt-0.5 text-xs text-[color:var(--color-text-muted)]">
                    {c.memberCount} member{c.memberCount === 1 ? "" : "s"} · {formatRelativeTime(c.updatedAt)}
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <Badge variant="outline">{c.confidence.replace(/_/g, " ")}</Badge>
                  <StatusBadge status={c.status} />
                  {c.status === "accepted" && c.acceptedInvestigationId && (
                    <Link
                      to={`/investigations/${c.acceptedInvestigationId}`}
                      className="flex items-center gap-1 text-xs font-medium text-[color:var(--color-accent)]"
                    >
                      View investigation <ArrowRight className="size-3" />
                    </Link>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
      </div>
    </div>
  );
}
