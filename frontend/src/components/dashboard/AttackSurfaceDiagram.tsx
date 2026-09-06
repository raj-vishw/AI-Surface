import { useMemo } from "react";
import { ReactFlow, Background, BackgroundVariant, type Node, type Edge, Position } from "@xyflow/react";
import "@xyflow/react/dist/style.css";

const STAGES = [
  { id: "domain", label: "Domain" },
  { id: "subdomain", label: "Subdomain" },
  { id: "ip", label: "IP" },
  { id: "service", label: "Service" },
  { id: "endpoint", label: "Endpoint" },
  { id: "finding", label: "Finding" },
];

/** The landing page's visual (spec §11): a subtle, professional attack-
 * surface topology — domain → subdomain → IP → service → endpoint →
 * finding — rendered read-only (no interaction chrome) via React Flow.
 * Not a decorative stock graphic; the shape mirrors this platform's own
 * real discovery pipeline (see docs/architecture/overview.md). */
export function AttackSurfaceDiagram() {
  const nodes = useMemo<Node[]>(
    () =>
      STAGES.map((s, i) => ({
        id: s.id,
        position: { x: i * 190, y: i % 2 === 0 ? 0 : 46 },
        data: { label: s.label },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
        style: {
          background: "var(--color-surface-elevated)",
          border: "1px solid var(--color-border-strong)",
          borderRadius: 8,
          color: "var(--color-text)",
          fontSize: 12,
          fontWeight: 600,
          padding: "8px 14px",
          width: 132,
        },
      })),
    [],
  );

  const edges = useMemo<Edge[]>(
    () =>
      STAGES.slice(1).map((s, i) => ({
        id: `${STAGES[i].id}-${s.id}`,
        source: STAGES[i].id,
        target: s.id,
        animated: true,
        style: { stroke: "var(--color-accent)", opacity: 0.5 },
      })),
    [],
  );

  return (
    <div className="h-64 w-full sm:h-72">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        fitViewOptions={{ padding: 0.3 }}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        panOnDrag={false}
        zoomOnScroll={false}
        zoomOnPinch={false}
        zoomOnDoubleClick={false}
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} color="var(--color-border)" gap={20} size={1} />
      </ReactFlow>
    </div>
  );
}
