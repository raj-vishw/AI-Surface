import { useParams, useNavigate, Link } from "react-router-dom";
import { ArrowLeft, ExternalLink } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { ErrorState } from "@/components/common/ErrorState";
import { Button } from "@/components/ui/Button";
import { Card, CardContent } from "@/components/ui/Card";
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { CardSkeleton } from "@/components/ui/Skeleton";
import { useFinding } from "@/hooks/useFindings";
import { useAsset } from "@/hooks/useAssets";
import { assetDisplayName } from "@/types/asset";
import { formatTimestamp } from "@/lib/utils";

export default function FindingDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: finding, isLoading, isError, error, refetch } = useFinding(id);
  const { data: asset } = useAsset(finding?.assetId);

  if (isError) return <ErrorState error={error} onRetry={refetch} />;
  if (isLoading || !finding) {
    return (
      <div>
        <PageHeader title="Finding" />
        <CardSkeleton />
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title={finding.title}
        description={
          <span className="flex items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <StatusBadge status={finding.status} />
          </span>
        }
        actions={
          <Button variant="outline" size="sm" onClick={() => navigate("/findings")}>
            <ArrowLeft className="size-3.5" /> Back to findings
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-4 p-6 lg:grid-cols-[2fr_1fr]">
        <div className="space-y-4">
          {/* Evidence — separated clearly from analysis/recommendation (spec §26) */}
          <Card>
            <CardContent>
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-[color:var(--color-text-faint)]">Evidence</p>
              <p className="text-sm leading-relaxed text-[color:var(--color-text)]">{finding.description}</p>
              {asset && (
                <Link to={`/assets/${asset.id}`} className="mt-3 inline-flex items-center gap-1.5 text-xs text-[color:var(--color-accent)]">
                  Affected asset: <span className="font-technical">{assetDisplayName(asset)}</span>
                  <ExternalLink className="size-3" />
                </Link>
              )}
            </CardContent>
          </Card>

          {/* Analysis */}
          <Card>
            <CardContent>
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-[color:var(--color-text-faint)]">Analysis</p>
              <dl className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <dt className="text-xs text-[color:var(--color-text-faint)]">Detector</dt>
                  <dd className="font-technical text-[color:var(--color-text)]">{finding.detectorId}</dd>
                </div>
                <div>
                  <dt className="text-xs text-[color:var(--color-text-faint)]">Confidence</dt>
                  <dd className="text-[color:var(--color-text)]">{Math.round(finding.confidence * 100)}%</dd>
                </div>
                <div>
                  <dt className="text-xs text-[color:var(--color-text-faint)]">Effective severity</dt>
                  <dd><SeverityBadge severity={finding.severity} /></dd>
                </div>
                <div>
                  <dt className="text-xs text-[color:var(--color-text-faint)]">Detector severity</dt>
                  <dd><SeverityBadge severity={finding.detectorSeverity} /></dd>
                </div>
              </dl>
              {finding.severityOverridden && (
                <p className="mt-3 rounded-md border border-[color:var(--color-warning)]/30 bg-[color:var(--color-warning-muted)] px-3 py-2 text-xs text-[color:var(--color-warning)]">
                  Severity overridden by an analyst: {finding.severityOverrideReason}
                </p>
              )}
            </CardContent>
          </Card>

          {/* Recommendation */}
          <Card>
            <CardContent>
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-[color:var(--color-text-faint)]">Recommendation</p>
              <p className="text-sm leading-relaxed text-[color:var(--color-text)]">{finding.remediation}</p>
              {finding.references.length > 0 && (
                <ul className="mt-3 space-y-1">
                  {finding.references.map((ref) => (
                    <li key={ref.url}>
                      <a href={ref.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-[color:var(--color-accent)]">
                        {ref.label} <ExternalLink className="size-3" />
                      </a>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-4">
          <Card>
            <CardContent className="space-y-3">
              <p className="text-xs font-semibold uppercase tracking-wide text-[color:var(--color-text-faint)]">Timeline</p>
              <TimelineRow label="First seen" value={formatTimestamp(finding.firstSeen)} />
              <TimelineRow label="Last seen" value={formatTimestamp(finding.lastSeen)} />
              {finding.resolvedAt && <TimelineRow label="Resolved" value={formatTimestamp(finding.resolvedAt)} />}
              <TimelineRow label="Created" value={formatTimestamp(finding.createdAt)} />
              <TimelineRow label="Updated" value={formatTimestamp(finding.updatedAt)} />
            </CardContent>
          </Card>
          {finding.suppressionReason && (
            <Card>
              <CardContent>
                <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-[color:var(--color-text-faint)]">Suppression reason</p>
                <p className="text-sm text-[color:var(--color-text-muted)]">{finding.suppressionReason}</p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

function TimelineRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between text-sm">
      <span className="text-[color:var(--color-text-faint)]">{label}</span>
      <span className="font-technical text-[color:var(--color-text)]">{value}</span>
    </div>
  );
}
