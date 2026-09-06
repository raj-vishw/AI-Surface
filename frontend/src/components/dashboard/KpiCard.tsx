import type { LucideIcon } from "lucide-react";
import { TrendingDown, TrendingUp } from "lucide-react";
import { Link } from "react-router-dom";
import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/Skeleton";

interface KpiCardProps {
  label: string;
  value: number | string;
  icon: LucideIcon;
  href?: string;
  tone?: "neutral" | "danger" | "warning" | "success";
  trend?: { value: number; direction: "up" | "down"; goodDirection: "up" | "down" };
  isLoading?: boolean;
}

const TONE_STYLES: Record<NonNullable<KpiCardProps["tone"]>, string> = {
  neutral: "text-[color:var(--color-text)]",
  danger: "text-[color:var(--color-danger)]",
  warning: "text-[color:var(--color-warning)]",
  success: "text-[color:var(--color-success)]",
};

/** A high-density KPI card (spec §14): current value + trend + status —
 * never fabricated (the backing hook returns real aggregate counts). */
export function KpiCard({ label, value, icon: Icon, href, tone = "neutral", trend, isLoading }: KpiCardProps) {
  const content = (
    <div className="flex h-full flex-col justify-between rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-4 transition-colors hover:border-[color:var(--color-border-strong)]">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-[color:var(--color-text-muted)]">{label}</p>
        <Icon className="size-4 text-[color:var(--color-text-faint)]" aria-hidden="true" />
      </div>
      {isLoading ? (
        <Skeleton className="mt-2 h-7 w-16" />
      ) : (
        <div className="mt-1 flex items-baseline gap-2">
          <span className={cn("font-technical text-2xl font-bold", TONE_STYLES[tone])}>{value}</span>
          {trend && (
            <span
              className={cn(
                "flex items-center gap-0.5 text-xs font-medium",
                trend.direction === trend.goodDirection ? "text-[color:var(--color-success)]" : "text-[color:var(--color-danger)]",
              )}
            >
              {trend.direction === "up" ? <TrendingUp className="size-3" /> : <TrendingDown className="size-3" />}
              {trend.value}%
            </span>
          )}
        </div>
      )}
    </div>
  );

  if (!href) return content;
  return (
    <Link to={href} className="block">
      {content}
    </Link>
  );
}
