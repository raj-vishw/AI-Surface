import { useMemo, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { ReactFlow, Background, BackgroundVariant, type Node, type NodeMouseHandler } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useAssetAnalytics } from "@/hooks/useAnalytics";
import { Skeleton } from "@/components/ui/Skeleton";

const ANGLE_STEP = (2 * Math.PI) / 8;

/** Interactive attack-surface overview (spec §15): each node is a real
 * asset-type count from internal/analytics.AssetAnalytics.ByType, laid
 * out radially around the target; clicking navigates to the filtered
 * Assets list — a real drill-down, not a decorative graphic. */
export function AttackSurfaceOverview() {
  const { data, isLoading } = useAssetAnalytics();
  const navigate = useNavigate();

  const nodes = useMemo<Node[]>(() => {
    if (!data) return [];
    const center: Node = {
      id: "center",
      position: { x: 0, y: 0 },
      data: { label: "Target" },
      style: {
        background: "var(--color-accent-muted)",
        border: "1px solid var(--color-accent)",
        borderRadius: 999,
        color: "var(--color-accent-strong)",
        fontSize: 11,
        fontWeight: 700,
        padding: "10px 4px",
        width: 72,
        height: 72,
        textAlign: "center",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      },
      draggable: false,
    };
    const radius = 150;
    const typeNodes: Node[] = data.byType.slice(0, 8).map((t, i) => {
      const angle = i * ANGLE_STEP;
      return {
        id: t.name,
        position: { x: Math.cos(angle) * radius, y: Math.sin(angle) * radius },
        data: { label: `${t.name}\n${t.count}` },
        style: {
          background: "var(--color-surface-elevated)",
          border: "1px solid var(--color-border-strong)",
          borderRadius: 8,
          color: "var(--color-text)",
          fontSize: 10.5,
          fontWeight: 600,
          padding: "8px 10px",
          width: 96,
          textAlign: "center",
          whiteSpace: "pre-line",
          cursor: "pointer",
        },
        draggable: false,
      };
    });
    return [center, ...typeNodes];
  }, [data]);

  const edges = useMemo(
    () =>
      nodes
        .filter((n) => n.id !== "center")
        .map((n) => ({
          id: `center-${n.id}`,
          source: "center",
          target: n.id,
          style: { stroke: "var(--color-border-strong)" },
        })),
    [nodes],
  );

  const onNodeClick = useCallback<NodeMouseHandler>(
    (_, node) => {
      if (node.id === "center") return;
      navigate(`/assets?type=${encodeURIComponent(node.id)}`);
    },
    [navigate],
  );

  if (isLoading) return <Skeleton className="h-72 w-full" />;

  if (!data || data.total === 0) {
    return (
      <div className="flex h-72 items-center justify-center text-sm text-[color:var(--color-text-muted)]">
        No assets discovered for this target yet.
      </div>
    );
  }

  return (
    <div className="h-72 w-full">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodeClick={onNodeClick}
        fitView
        fitViewOptions={{ padding: 0.25 }}
        nodesDraggable={false}
        elementsSelectable={false}
        panOnScroll
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} color="var(--color-border)" gap={20} size={1} />
      </ReactFlow>
    </div>
  );
}
