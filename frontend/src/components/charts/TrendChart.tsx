import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Bucket } from "@/types/analytics";

interface TrendChartProps {
  data: Bucket[];
  color?: string;
  label?: string;
  height?: number;
}

function formatAxisDate(value: string): string {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return `${d.getMonth() + 1}/${d.getDate()}`;
}

/** A readable trend line with tooltips and axes (spec §33: "Charts must
 * have tooltips, legends where useful, readable axes, filters, date
 * ranges") — reused across Analytics/Risk/Dashboard rather than each
 * page building its own chart. */
export function TrendChart({ data, color = "var(--color-accent)", label = "Count", height = 220 }: TrendChartProps) {
  if (data.length === 0) {
    return <p className="flex h-48 items-center justify-center text-sm text-[color:var(--color-text-muted)]">No data for this range.</p>;
  }
  return (
    <div style={{ height }} className="w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity={0.35} />
              <stop offset="100%" stopColor={color} stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 3" vertical={false} />
          <XAxis
            dataKey="bucketStart"
            tickFormatter={formatAxisDate}
            stroke="var(--color-text-faint)"
            fontSize={11}
            tickLine={false}
            axisLine={false}
          />
          <YAxis stroke="var(--color-text-faint)" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
          <Tooltip
            labelFormatter={(v) => new Date(v as string).toLocaleDateString()}
            formatter={(value) => [value, label] as [number, string]}
            contentStyle={{
              background: "var(--color-surface-elevated)",
              border: "1px solid var(--color-border-strong)",
              borderRadius: 6,
              fontSize: 12,
            }}
            itemStyle={{ color: "var(--color-text)" }}
            labelStyle={{ color: "var(--color-text-muted)" }}
          />
          <Area type="monotone" dataKey="count" stroke={color} fill="url(#trendFill)" strokeWidth={2} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
