import type { ReactNode } from "react";

interface PageHeaderProps {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
}

export function PageHeader({ title, description, actions }: PageHeaderProps) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3 border-b border-[color:var(--color-border)] px-6 py-4">
      <div>
        <h1 className="text-lg font-semibold text-[color:var(--color-text)]">{title}</h1>
        {description && <p className="mt-0.5 text-sm text-[color:var(--color-text-muted)]">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}
