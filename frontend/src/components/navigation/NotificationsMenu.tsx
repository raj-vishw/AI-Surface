import { Link } from "react-router-dom";
import { Bell } from "lucide-react";
import { useAlerts } from "@/hooks/useAlerts";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/DropdownMenu";
import { SeverityBadge } from "@/components/ui/Badge";
import { formatRelativeTime } from "@/lib/utils";

/** Surfaces open critical/high alerts as notifications — real data from
 * the alert pipeline, not a fabricated notification feed (this backend
 * has no separate notifications concept — see docs/architecture/
 * detection-engine.md's alert model, which is exactly what this reads). */
export function NotificationsMenu() {
  const { data } = useAlerts({ status: "open" });
  const urgent = (data?.items ?? []).filter((a) => a.severity === "critical" || a.severity === "high").slice(0, 6);

  return (
    <DropdownMenu>
      <DropdownMenuTrigger className="relative flex size-8 items-center justify-center rounded-md text-[color:var(--color-text-muted)] hover:bg-[color:var(--color-surface-hover)] hover:text-[color:var(--color-text)] focus-visible:outline-none">
        <Bell className="size-4" aria-hidden="true" />
        {urgent.length > 0 && (
          <span className="absolute right-1 top-1 flex size-2 rounded-full bg-[color:var(--color-danger)]" />
        )}
        <span className="sr-only">Notifications</span>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-80">
        <DropdownMenuLabel>Open critical &amp; high alerts</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {urgent.length === 0 && (
          <p className="px-2 py-4 text-center text-xs text-[color:var(--color-text-muted)]">No urgent alerts right now.</p>
        )}
        {urgent.map((alert) => (
          <DropdownMenuItem key={alert.id} asChild>
            <Link to="/alerts" className="flex flex-col items-start gap-1">
              <div className="flex w-full items-center justify-between gap-2">
                <SeverityBadge severity={alert.severity} />
                <span className="text-[0.65rem] text-[color:var(--color-text-faint)]">{formatRelativeTime(alert.lastObservedAt)}</span>
              </div>
              <p className="line-clamp-2 text-left text-xs text-[color:var(--color-text)]">{alert.title}</p>
            </Link>
          </DropdownMenuItem>
        ))}
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <Link to="/alerts" className="justify-center text-xs text-[color:var(--color-accent)]">
            View all alerts
          </Link>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
