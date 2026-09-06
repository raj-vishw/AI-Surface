import { Menu, Search, ShieldHalf } from "lucide-react";
import { Link } from "react-router-dom";
import { useWorkspaceStore } from "@/store/workspace";
import { TargetSwitcher } from "@/components/navigation/TargetSwitcher";
import { NotificationsMenu } from "@/components/navigation/NotificationsMenu";
import { SystemStatus } from "@/components/navigation/SystemStatus";
import { UserMenu } from "@/components/navigation/UserMenu";
import { openCommandPalette } from "@/components/navigation/command-palette-events";

export function Navbar() {
  const setMobileSidebarOpen = useWorkspaceStore((s) => s.setMobileSidebarOpen);

  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b border-[color:var(--color-border)] bg-[color:var(--color-bg)] px-3">
      <button
        type="button"
        className="flex size-8 items-center justify-center rounded-md text-[color:var(--color-text-muted)] hover:bg-[color:var(--color-surface-hover)] md:hidden"
        onClick={() => setMobileSidebarOpen(true)}
        aria-label="Open navigation"
      >
        <Menu className="size-5" />
      </button>

      <Link to="/" className="flex items-center gap-2 md:hidden">
        <ShieldHalf className="size-5 text-[color:var(--color-accent)]" />
      </Link>

      <TargetSwitcher />

      <button
        type="button"
        onClick={openCommandPalette}
        className="ml-1 flex h-8 flex-1 max-w-md items-center gap-2 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-2.5 text-sm text-[color:var(--color-text-faint)] hover:bg-[color:var(--color-surface-hover)]"
      >
        <Search className="size-3.5" aria-hidden="true" />
        <span className="hidden sm:inline">Search assets, findings, investigations...</span>
        <span className="sm:hidden">Search</span>
        <kbd className="ml-auto hidden rounded border border-[color:var(--color-border)] px-1.5 py-0.5 text-[0.65rem] sm:inline">
          ⌘K
        </kbd>
      </button>

      <div className="ml-auto flex items-center gap-2">
        <SystemStatus />
        <NotificationsMenu />
        <div className="mx-1 h-5 w-px bg-[color:var(--color-border)]" />
        <UserMenu />
      </div>
    </header>
  );
}
