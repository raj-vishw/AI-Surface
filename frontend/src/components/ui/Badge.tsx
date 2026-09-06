import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";
import { SEVERITY_STYLES, statusStyle, type Severity } from "@/lib/severity";

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  variant?: "neutral" | "outline";
}

/** Generic badge — for anything that isn't a severity/status (which have
 * their own dedicated components below, per spec §5/§56's "define
 * tokens centrally, never per-component"). */
export function Badge({ className, variant = "neutral", ...props }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium",
        variant === "neutral" && "bg-[color:var(--color-surface-elevated)] text-[color:var(--color-text-muted)] border border-[color:var(--color-border)]",
        variant === "outline" && "border border-[color:var(--color-border-strong)] text-[color:var(--color-text)]",
        className,
      )}
      {...props}
    />
  );
}

const SEVERITY_ICON: Record<Severity, string> = {
  critical: "●",
  high: "●",
  medium: "●",
  low: "●",
  informational: "○",
};

/** The ONE severity badge used everywhere in the app (spec §56: "Use
 * icons and text in addition to color" — never color alone). */
export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const style = SEVERITY_STYLES[severity];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-semibold",
        style.text,
        style.bg,
        style.border,
        className,
      )}
    >
      <span aria-hidden="true" className="text-[0.6rem]">
        {SEVERITY_ICON[severity]}
      </span>
      {style.label}
    </span>
  );
}

/** The ONE status badge used everywhere in the app. */
export function StatusBadge({ status, className }: { status: string | null | undefined; className?: string }) {
  const style = statusStyle(status);
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium", style.text, style.bg, className)}>
      <span aria-hidden="true" className="size-1.5 rounded-full bg-current" />
      {style.label}
    </span>
  );
}
