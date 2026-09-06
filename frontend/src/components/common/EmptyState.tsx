import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  description: string;
  action?: ReactNode;
  className?: string;
}

/** Excellent empty states (spec §46): explains what's shown, why it's
 * empty, and what to do next — never a bare "No data". */
export function EmptyState({ icon: Icon, title, description, action, className }: EmptyStateProps) {
  return (
    <div className={cn("flex flex-col items-center justify-center gap-3 px-6 py-14 text-center", className)}>
      <div className="flex size-11 items-center justify-center rounded-full bg-[color:var(--color-surface-elevated)] border border-[color:var(--color-border)]">
        <Icon className="size-5 text-[color:var(--color-text-faint)]" aria-hidden="true" />
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium text-[color:var(--color-text)]">{title}</p>
        <p className="max-w-sm text-sm text-[color:var(--color-text-muted)]">{description}</p>
      </div>
      {action}
    </div>
  );
}
