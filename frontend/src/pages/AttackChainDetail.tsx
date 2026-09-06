import { useMemo, useState, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { ReactFlow, Background, BackgroundVariant, type Node, type Edge, Position, type NodeMouseHandler } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { ArrowLeft } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { ErrorState } from "@/components/common/ErrorState";
import { Button } from "@/components/ui/Button";
import { SeverityBadge, StatusBadge, Badge } from "@/components/ui/Badge";
import { Drawer, DrawerContent, DrawerTitle, DrawerDescription } from "@/components/ui/Drawer";
import { CardSkeleton } from "@/components/ui/Skeleton";
import { Card, CardContent } from "@/components/ui/Card";
import { useAttackChain, useAttackChainStages } from "@/hooks/useCorrelations";
import { STAGE_LABELS, type AttackChainStage } from "@/types/correlation";

export default function AttackChainDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: chain, isLoading, isError, error, refetch } = useAttackChain(id);
  const { data: stages } = useAttackChainStages(id);
  const [selected, setSelected] = useState<AttackChainStage | null>(null);

  const nodes = useMemo<Node[]>(() => {
    if (!stages) return [];
    return stages.map((s, i) => ({
      id: s.id,
      position: { x: i * 210, y: 0 },
      data: { label: STAGE_LABELS[s.stage] },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
      draggable: false,
      style: {
        background: "var(--color-surface-elevated)",
        border: `1.5px solid var(--color-accent)`,
        borderRadius: 8,
        color: "var(--color-text)",
        fontSize: 12,
        fontWeight: 600,
        padding: "10px 16px",
        width: 160,
        cursor: "pointer",
      },
    }));
  }, [stages]);

  const edges = useMemo<Edge[]>(() => {
    if (!stages) return [];
    return stages.slice(1).map((s, i) => ({
      id: `${stages[i].id}-${s.id}`,
      source: stages[i].id,
      target: s.id,
      animated: true,
      style: { stroke: "var(--color-accent)" },
    }));
  }, [stages]);

  const onNodeClick = useCallback<NodeMouseHandler>(
    (_, node) => {
      const stage = stages?.find((s) => s.id === node.id);
      if (stage) setSelected(stage);
    },
    [stages],
  );

  if (isError) return <ErrorState error={error} onRetry={refetch} />;
  if (isLoading || !chain) {
    return (
      <div>
        <PageHeader title="Attack Chain" />
        <CardSkeleton />
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title={chain.name}
        description={
          <span className="flex items-center gap-2">
            <SeverityBadge severity={chain.severity} />
            <StatusBadge status={chain.status} />
            <Badge variant="outline">{chain.confidence} confidence</Badge>
          </span>
        }
        actions={
          <Button variant="outline" size="sm" onClick={() => navigate("/attack-chains")}>
            <ArrowLeft className="size-3.5" /> Back
          </Button>
        }
      />

      <div className="space-y-4 p-6">
        <Card>
          <CardContent>
            <p className="text-sm leading-relaxed text-[color:var(--color-text-muted)]">{chain.description}</p>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-0">
            <div className="h-64 w-full">
              <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodeClick={onNodeClick}
                fitView
                fitViewOptions={{ padding: 0.3 }}
                nodesDraggable={false}
                panOnScroll
                proOptions={{ hideAttribution: true }}
              >
                <Background variant={BackgroundVariant.Dots} color="var(--color-border)" gap={20} size={1} />
              </ReactFlow>
            </div>
          </CardContent>
        </Card>
      </div>

      <Drawer open={!!selected} onOpenChange={(open) => !open && setSelected(null)}>
        <DrawerContent>
          {selected && (
            <>
              <DrawerTitle>{STAGE_LABELS[selected.stage]}</DrawerTitle>
              <DrawerDescription className="mb-4">Stage {selected.order + 1} of this attack chain</DrawerDescription>
              <div className="space-y-3 text-sm">
                <div className="flex items-center justify-between">
                  <span className="text-[color:var(--color-text-faint)]">Confidence</span>
                  <span className="text-[color:var(--color-text)]">{selected.confidence}</span>
                </div>
                <div>
                  <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-[color:var(--color-text-faint)]">Evidence</p>
                  <ul className="space-y-1.5">
                    {selected.evidence.map((ev, i) => (
                      <li key={i} className="rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-2.5 py-1.5 font-technical text-xs text-[color:var(--color-text-muted)]">
                        {ev.type}: {ev.id}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </>
          )}
        </DrawerContent>
      </Drawer>
    </div>
  );
}
