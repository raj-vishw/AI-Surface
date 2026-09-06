import { NavLink } from "react-router-dom";
import { ChevronsLeft, ShieldHalf } from "lucide-react";
import { cn } from "@/lib/utils";
import { useWorkspaceStore } from "@/store/workspace";
import { NAV_GROUPS } from "@/components/navigation/nav-config";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/Tooltip";

function SidebarLink({ href, icon: Icon, label, collapsed }: { href: string; icon: typeof ShieldHalf; label: string; collapsed: boolean }) {
  const link = (
    <NavLink
      to={href}
      className={({ isActive }) =>
        cn(
          "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm font-medium transition-colors",
          collapsed && "justify-center px-0",
          isActive
            ? "bg-[color:var(--color-accent-muted)] text-[color:var(--color-accent-strong)]"
            : "text-[color:var(--color-text-muted)] hover:bg-[color:var(--color-surface-hover)] hover:text-[color:var(--color-text)]",
        )
      }
    >
      <Icon className="size-4 shrink-0" aria-hidden="true" />
      {!collapsed && <span className="truncate">{label}</span>}
    </NavLink>
  );

  if (!collapsed) return link;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{link}</TooltipTrigger>
      <TooltipContent side="right">{label}</TooltipContent>
    </Tooltip>
  );
}

export function SidebarContent({ collapsed, onToggle }: { collapsed: boolean; onToggle?: () => void }) {
  return (
    <div className="flex h-full flex-col">
      <div className={cn("flex items-center gap-2 px-3 py-4", collapsed && "justify-center px-0")}>
        <div className="flex size-7 shrink-0 items-center justify-center rounded-md bg-[color:var(--color-accent-muted)]">
          <ShieldHalf className="size-4 text-[color:var(--color-accent)]" aria-hidden="true" />
        </div>
        {!collapsed && <span className="text-sm font-bold tracking-tight text-[color:var(--color-text)]">AI-RECON</span>}
      </div>

      <nav className="flex-1 space-y-4 overflow-y-auto px-2 pb-4">
        {NAV_GROUPS.map((group) => (
          <div key={group.label}>
            {!collapsed && (
              <p className="px-2.5 pb-1.5 text-[0.65rem] font-semibold uppercase tracking-wider text-[color:var(--color-text-faint)]">
                {group.label}
              </p>
            )}
            <div className="space-y-0.5">
              {group.items.map((item) => (
                <SidebarLink key={item.href} {...item} collapsed={collapsed} />
              ))}
            </div>
          </div>
        ))}
      </nav>

      {onToggle && (
        <button
          type="button"
          onClick={onToggle}
          className={cn(
            "flex items-center gap-2 border-t border-[color:var(--color-border)] px-3 py-3 text-xs text-[color:var(--color-text-faint)] hover:text-[color:var(--color-text)]",
            collapsed && "justify-center",
          )}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          <ChevronsLeft className={cn("size-4 transition-transform", collapsed && "rotate-180")} />
          {!collapsed && "Collapse"}
        </button>
      )}
    </div>
  );
}

export function Sidebar() {
  const collapsed = useWorkspaceStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useWorkspaceStore((s) => s.toggleSidebar);

  return (
    <aside
      className={cn(
        "hidden shrink-0 border-r border-[color:var(--color-border)] bg-[color:var(--color-bg)] transition-[width] duration-150 md:block",
        collapsed ? "w-14" : "w-60",
      )}
    >
      <SidebarContent collapsed={collapsed} onToggle={toggleSidebar} />
    </aside>
  );
}
