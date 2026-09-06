import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { SEVERITY_STYLES, type Severity } from "@/lib/severity";
import type { NamedCount } from "@/types/analytics";

/** Severity distribution — the ONE place this chart's colors are chosen,
 * pulled from the same central severity token map every badge uses
 * (spec §5/§16). */
export function SeverityDistributionChart({ data }: { data: NamedCount[] }) {
  const chartData = data.map((d) => ({
    ...d,
    fill: SEVERITY_STYLES[(d.name as Severity) in SEVERITY_STYLES ? (d.name as Severity) : "informational"].raw,
  }));

  if (data.length === 0 || data.every((d) => d.count === 0)) {
    return <p className="flex h-48 items-center justify-center text-sm text-[color:var(--color-text-muted)]">No data for this range.</p>;
  }

  return (
    <div className="h-48 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie data={chartData} dataKey="count" nameKey="name" innerRadius={48} outerRadius={72} paddingAngle={2} strokeWidth={0}>
            {chartData.map((entry) => (
              <Cell key={entry.name} fill={entry.fill} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: "var(--color-surface-elevated)",
              border: "1px solid var(--color-border-strong)",
              borderRadius: 6,
              fontSize: 12,
            }}
            itemStyle={{ color: "var(--color-text)" }}
            labelStyle={{ color: "var(--color-text-muted)" }}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
