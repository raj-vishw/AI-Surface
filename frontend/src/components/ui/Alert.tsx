import type { HTMLAttributes } from "react";
import { AlertTriangle, Info, XCircle, CheckCircle2 } from "lucide-react";
import { cn } from "@/lib/utils";

type AlertVariant = "info" | "warning" | "danger" | "success";

const VARIANT_STYLES: Record<AlertVariant, { icon: typeof Info; text: string; bg: string; border: string }> = {
  info: { icon: Info, text: "text-[color:var(--color-info)]", bg: "bg-[color:var(--color-info-muted)]", border: "border-[color:var(--color-info)]/30" },
  warning: { icon: AlertTriangle, text: "text-[color:var(--color-warning)]", bg: "bg-[color:var(--color-warning-muted)]", border: "border-[color:var(--color-warning)]/30" },
  danger: { icon: XCircle, text: "text-[color:var(--color-danger)]", bg: "bg-[color:var(--color-danger-muted)]", border: "border-[color:var(--color-danger)]/30" },
  success: { icon: CheckCircle2, text: "text-[color:var(--color-success)]", bg: "bg-[color:var(--color-success-muted)]", border: "border-[color:var(--color-success)]/30" },
};

interface AlertProps extends HTMLAttributes<HTMLDivElement> {
  variant?: AlertVariant;
  title?: string;
}

export function Alert({ variant = "info", title, className, children, ...props }: AlertProps) {
  const style = VARIANT_STYLES[variant];
  const Icon = style.icon;
  return (
    <div role="alert" className={cn("flex gap-2.5 rounded-md border px-3 py-2.5 text-sm", style.bg, style.border, className)} {...props}>
      <Icon className={cn("mt-0.5 size-4 shrink-0", style.text)} aria-hidden="true" />
      <div className="space-y-0.5">
        {title && <p className={cn("font-medium", style.text)}>{title}</p>}
        {children && <div className="text-[color:var(--color-text-muted)]">{children}</div>}
      </div>
    </div>
  );
}
