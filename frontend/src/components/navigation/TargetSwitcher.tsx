import { Check, ChevronsUpDown, Globe2 } from "lucide-react";
import { useTargets } from "@/hooks/useWorkspace";
import { useWorkspaceStore } from "@/store/workspace";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/DropdownMenu";
import { Skeleton } from "@/components/ui/Skeleton";

export function TargetSwitcher() {
  const { data: targets, isLoading } = useTargets();
  const currentTargetId = useWorkspaceStore((s) => s.currentTargetId);
  const setCurrentTargetId = useWorkspaceStore((s) => s.setCurrentTargetId);

  if (isLoading) return <Skeleton className="h-8 w-40" />;

  const current = targets?.find((t) => t.id === currentTargetId);

  return (
    <DropdownMenu>
      <DropdownMenuTrigger className="flex items-center gap-2 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-2.5 py-1.5 text-sm hover:bg-[color:var(--color-surface-hover)] focus-visible:outline-none">
        <Globe2 className="size-3.5 text-[color:var(--color-text-faint)]" aria-hidden="true" />
        <span className="max-w-[10rem] truncate font-medium text-[color:var(--color-text)]">
          {current?.name ?? "Select target"}
        </span>
        <ChevronsUpDown className="size-3.5 text-[color:var(--color-text-faint)]" aria-hidden="true" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-64">
        <DropdownMenuLabel>Targets</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {targets?.map((t) => (
          <DropdownMenuItem key={t.id} onSelect={() => setCurrentTargetId(t.id)}>
            <Check className={`size-3.5 ${t.id === currentTargetId ? "opacity-100" : "opacity-0"}`} />
            <div className="min-w-0 flex-1">
              <p className="truncate font-medium">{t.name}</p>
              <p className="truncate font-technical text-xs text-[color:var(--color-text-faint)]">{t.value}</p>
            </div>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
