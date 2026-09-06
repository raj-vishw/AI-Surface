import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { NamedCount } from "@/types/analytics";

export function NamedCountBarChart({ data, color = "var(--color-accent)", height = 240 }: { data: NamedCount[]; color?: string; height?: number }) {
  if (data.length === 0) {
    return <p className="flex h-40 items-center justify-center text-sm text-[color:var(--color-text-muted)]">No data available.</p>;
  }
  return (
    <div style={{ height }} className="w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16 }}>
          <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 3" horizontal={false} />
          <XAxis type="number" stroke="var(--color-text-faint)" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
          <YAxis
            type="category"
            dataKey="name"
            stroke="var(--color-text-faint)"
            fontSize={11}
            tickLine={false}
            axisLine={false}
            width={140}
            tickFormatter={(v: string) => (v.length > 20 ? `${v.slice(0, 20)}…` : v)}
          />
          <Tooltip
            contentStyle={{ background: "var(--color-surface-elevated)", border: "1px solid var(--color-border-strong)", borderRadius: 6, fontSize: 12 }}
            itemStyle={{ color: "var(--color-text)" }}
            labelStyle={{ color: "var(--color-text-muted)" }}
          />
          <Bar dataKey="count" fill={color} radius={[0, 3, 3, 0]} maxBarSize={16} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
