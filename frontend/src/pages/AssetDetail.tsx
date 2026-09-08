import type { ReactNode } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { ArrowLeft, Globe2 } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { ErrorState } from "@/components/common/ErrorState";
import { EmptyState } from "@/components/common/EmptyState";
import { Button } from "@/components/ui/Button";
import { Card, CardContent } from "@/components/ui/Card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/Tabs";
import { StatusBadge, SeverityBadge, Badge } from "@/components/ui/Badge";
import { CardSkeleton } from "@/components/ui/Skeleton";
import { useAsset, useAssetFingerprints, useAssetFindings } from "@/hooks/useAssets";
import { assetDisplayName } from "@/types/asset";
import { formatTimestamp, truncateId } from "@/lib/utils";

export default function AssetDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: asset, isLoading, isError, error, refetch } = useAsset(id);
  const { data: fingerprints } = useAssetFingerprints(id);
  const { data: findings } = useAssetFindings(id);

  if (isError) return <ErrorState error={error} onRetry={refetch} />;
  if (isLoading || !asset) {
    return (
      <div>
        <PageHeader title="Asset" />
        <CardSkeleton />
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title={assetDisplayName(asset)}
        description={`${asset.type.replace(/_/g, " ")} · ${truncateId(asset.id)}`}
        actions={
          <Button variant="outline" size="sm" onClick={() => navigate("/assets")}>
            <ArrowLeft className="size-3.5" /> Back to assets
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-4 p-6 lg:grid-cols-[2fr_1fr]">
        <div className="space-y-4">
          <Tabs defaultValue="overview">
            <TabsList>
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="technologies">Technologies ({fingerprints?.length ?? 0})</TabsTrigger>
              <TabsTrigger value="findings">Findings ({findings?.length ?? 0})</TabsTrigger>
              <TabsTrigger value="metadata">Raw metadata</TabsTrigger>
            </TabsList>

            <TabsContent value="overview">
              <Card>
                <CardContent className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
                  <Field label="Hostname" value={asset.hostname} mono />
                  <Field label="IP address" value={asset.ip} mono />
                  <Field label="Port" value={asset.port?.toString()} mono />
                  <Field label="Protocol" value={asset.protocol} mono />
                  <Field label="URL" value={asset.url} mono />
                  <Field label="Technology" value={asset.technology} />
                  <Field label="Provider" value={asset.provider} />
                  <Field label="Model" value={asset.model} />
                  <Field label="Environment" value={asset.environment} />
                  <Field label="Source" value={asset.source} />
                  <Field label="Confidence" value={`${Math.round(asset.confidence * 100)}% (${asset.confidenceLevel})`} />
                  <Field label="Identity key" value={asset.identityKey} mono />
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="technologies">
              {!fingerprints || fingerprints.length === 0 ? (
                <EmptyState icon={Globe2} title="No technologies detected" description="No fingerprinting evidence has been recorded for this asset." />
              ) : (
                <div className="space-y-2">
                  {fingerprints.map((fp) => (
                    <Card key={fp.id}>
                      <CardContent className="flex items-center justify-between">
                        <div>
                          <p className="text-sm font-medium text-[color:var(--color-text)]">
                            {fp.technology} {fp.version && <span className="font-technical text-[color:var(--color-text-faint)]">v{fp.version}</span>}
                          </p>
                          <p className="text-xs text-[color:var(--color-text-faint)]">{fp.category.replace(/_/g, " ")} {fp.vendor && `· ${fp.vendor}`}</p>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge>{Math.round(fp.confidence * 100)}% confidence</Badge>
                          <StatusBadge status={fp.status.toLowerCase()} />
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </TabsContent>

            <TabsContent value="findings">
              {!findings || findings.length === 0 ? (
                <EmptyState icon={Globe2} title="No findings" description="No security findings have been recorded against this asset." />
              ) : (
                <div className="space-y-2">
                  {findings.map((f) => (
                    <Link key={f.id} to={`/findings/${f.id}`}>
                      <Card className="hover:border-[color:var(--color-border-strong)]">
                        <CardContent className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <SeverityBadge severity={f.severity} />
                            <p className="text-sm text-[color:var(--color-text)]">{f.title}</p>
                          </div>
                          <StatusBadge status={f.status} />
                        </CardContent>
                      </Card>
                    </Link>
                  ))}
                </div>
              )}
            </TabsContent>

            <TabsContent value="metadata">
              <Card>
                <CardContent>
                  <pre className="overflow-x-auto font-technical text-xs text-[color:var(--color-text-muted)]">
                    {JSON.stringify(asset.metadata ?? {}, null, 2)}
                  </pre>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>

        <div className="space-y-4">
          <Card>
            <CardContent className="space-y-3">
              <p className="text-xs font-semibold uppercase tracking-wide text-[color:var(--color-text-faint)]">Lifecycle</p>
              <Field label="Status" value={<StatusBadge status={asset.status.toLowerCase()} />} />
              <Field label="First seen" value={formatTimestamp(asset.firstSeen)} />
              <Field label="Last seen" value={formatTimestamp(asset.lastSeen)} />
              <Field label="Created" value={formatTimestamp(asset.createdAt)} />
              <Field label="Updated" value={formatTimestamp(asset.updatedAt)} />
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div>
      <p className="text-xs text-[color:var(--color-text-faint)]">{label}</p>
      <p className={mono ? "font-technical text-[color:var(--color-text)]" : "text-[color:var(--color-text)]"}>{value ?? "—"}</p>
    </div>
  );
}
