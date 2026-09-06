import { useParams, useNavigate } from "react-router-dom";
import { ArrowLeft, Clock, MessageSquare, Lightbulb, BrainCircuit } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { ErrorState } from "@/components/common/ErrorState";
import { EmptyState } from "@/components/common/EmptyState";
import { Button } from "@/components/ui/Button";
import { Card, CardContent } from "@/components/ui/Card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/Tabs";
import { SeverityBadge, StatusBadge, Badge } from "@/components/ui/Badge";
import { CardSkeleton } from "@/components/ui/Skeleton";
import {
  useInvestigation,
  useInvestigationTimeline,
  useInvestigationNotes,
  useInvestigationHypotheses,
} from "@/hooks/useInvestigations";
import { formatRelativeTime, formatTimestamp } from "@/lib/utils";

export default function InvestigationDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: inv, isLoading, isError, error, refetch } = useInvestigation(id);
  const { data: timeline } = useInvestigationTimeline(id);
  const { data: notes } = useInvestigationNotes(id);
  const { data: hypotheses } = useInvestigationHypotheses(id);

  if (isError) return <ErrorState error={error} onRetry={refetch} />;
  if (isLoading || !inv) {
    return (
      <div>
        <PageHeader title="Investigation" />
        <CardSkeleton />
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title={inv.title}
        description={
          <span className="flex items-center gap-2">
            <SeverityBadge severity={inv.severity} />
            <StatusBadge status={inv.status} />
            <Badge variant="outline">{inv.priority} priority</Badge>
          </span>
        }
        actions={
          <Button variant="outline" size="sm" onClick={() => navigate("/investigations")}>
            <ArrowLeft className="size-3.5" /> Back
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-4 p-6 lg:grid-cols-[2fr_1fr]">
        <div className="space-y-4">
          <Card>
            <CardContent>
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-[color:var(--color-text-faint)]">Description</p>
              <p className="text-sm leading-relaxed text-[color:var(--color-text)]">{inv.description}</p>
            </CardContent>
          </Card>

          <Tabs defaultValue="timeline">
            <TabsList>
              <TabsTrigger value="timeline">Timeline ({timeline?.length ?? 0})</TabsTrigger>
              <TabsTrigger value="notes">Notes ({notes?.length ?? 0})</TabsTrigger>
              <TabsTrigger value="hypotheses">Hypotheses ({hypotheses?.length ?? 0})</TabsTrigger>
            </TabsList>

            <TabsContent value="timeline">
              {!timeline || timeline.length === 0 ? (
                <EmptyState icon={Clock} title="No timeline events" description="Evidence, notes, and status changes will appear here as they're recorded." />
              ) : (
                <ol className="space-y-0 border-l border-[color:var(--color-border)] pl-4">
                  {timeline.map((event) => (
                    <li key={event.id} className="relative pb-5">
                      <span className="absolute -left-[21px] top-1 size-2.5 rounded-full border-2 border-[color:var(--color-bg)] bg-[color:var(--color-accent)]" />
                      <p className="text-sm text-[color:var(--color-text)]">{event.title}</p>
                      <p className="text-xs text-[color:var(--color-text-muted)]">{event.description}</p>
                      <p className="mt-0.5 text-[0.65rem] text-[color:var(--color-text-faint)]">
                        {event.actor} · {formatTimestamp(event.timestamp)}
                      </p>
                    </li>
                  ))}
                </ol>
              )}
            </TabsContent>

            <TabsContent value="notes">
              {!notes || notes.length === 0 ? (
                <EmptyState icon={MessageSquare} title="No notes" description="Analyst notes attached to this investigation will appear here." />
              ) : (
                <div className="space-y-2">
                  {notes.map((note) => (
                    <Card key={note.id}>
                      <CardContent>
                        <div className="mb-1.5 flex items-center gap-2">
                          <p className="text-xs font-medium text-[color:var(--color-text)]">{note.authorId}</p>
                          {note.aiGenerated && (
                            <span className="flex items-center gap-1 rounded-full bg-[color:var(--color-accent-muted)] px-1.5 py-0.5 text-[0.6rem] font-semibold text-[color:var(--color-accent-strong)]">
                              <BrainCircuit className="size-2.5" /> AI-generated
                            </span>
                          )}
                          <span className="ml-auto text-[0.65rem] text-[color:var(--color-text-faint)]">{formatRelativeTime(note.createdAt)}</span>
                        </div>
                        <p className="text-sm text-[color:var(--color-text-muted)]">{note.content}</p>
                        {note.aiGenerated && !note.approvedBy && (
                          <p className="mt-1.5 text-[0.65rem] font-medium text-[color:var(--color-warning)]">Unapproved — requires analyst review</p>
                        )}
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </TabsContent>

            <TabsContent value="hypotheses">
              {!hypotheses || hypotheses.length === 0 ? (
                <EmptyState icon={Lightbulb} title="No hypotheses" description="Propose a hypothesis via the CLI to track a theory of what happened." />
              ) : (
                <div className="space-y-2">
                  {hypotheses.map((h) => (
                    <Card key={h.id}>
                      <CardContent>
                        <div className="flex items-center justify-between">
                          <p className="text-sm font-medium text-[color:var(--color-text)]">{h.title}</p>
                          <StatusBadge status={h.status === "confirmed" ? "confirmed" : h.status === "refuted" ? "dismissed" : "candidate"} />
                        </div>
                        <p className="mt-1 text-xs text-[color:var(--color-text-muted)]">{h.description}</p>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </TabsContent>
          </Tabs>
        </div>

        <div className="space-y-4">
          <Card>
            <CardContent className="space-y-3 text-sm">
              <p className="text-xs font-semibold uppercase tracking-wide text-[color:var(--color-text-faint)]">Details</p>
              <Row label="Created by" value={inv.createdBy} />
              <Row label="Assigned to" value={inv.assignedTo} />
              <Row label="Confidence" value={inv.confidence.replace(/_/g, " ")} />
              <Row label="Version" value={`v${inv.version}`} />
              <Row label="Detected" value={inv.detectedAt ? formatTimestamp(inv.detectedAt) : "—"} />
              <Row label="Created" value={formatTimestamp(inv.createdAt)} />
              {inv.closedAt && <Row label="Closed" value={formatTimestamp(inv.closedAt)} />}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-[color:var(--color-text-faint)]">{label}</span>
      <span className="text-[color:var(--color-text)]">{value}</span>
    </div>
  );
}
