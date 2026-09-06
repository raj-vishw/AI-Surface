import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Command } from "cmdk";
import {
  LayoutDashboard,
  Globe,
  ShieldAlert,
  Search as SearchIcon,
  Radar,
  BrainCircuit,
  FileText,
} from "lucide-react";
import { useGlobalSearch } from "@/hooks/useSearch";
import { useStartScan } from "@/hooks/useScans";
import { useTargets } from "@/hooks/useWorkspace";
import { useWorkspaceStore } from "@/store/workspace";
import { COMMAND_PALETTE_EVENT } from "./command-palette-events";

const STATIC_COMMANDS = [
  { label: "Go to Dashboard", href: "/dashboard", icon: LayoutDashboard },
  { label: "Search Assets", href: "/assets", icon: Globe },
  { label: "Search Findings", href: "/findings", icon: ShieldAlert },
  { label: "Open Investigations", href: "/investigations", icon: SearchIcon },
  { label: "Open Reconnaissance", href: "/reconnaissance", icon: Radar },
  { label: "Open AI Assistant", href: "/ai", icon: BrainCircuit },
  { label: "Open Reports", href: "/reports", icon: FileText },
];

/**
 * Combined global search (spec §52) + command palette (spec §53): the
 * same Cmd/Ctrl+K dialog shows navigation commands when empty and
 * grouped entity results (spec §52's "Assets (3) / Findings (2) / ...")
 * once a query is typed, backed by src/api/search.ts's real (if
 * currently mock-backed) entity search.
 */
export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const navigate = useNavigate();
  const { data: groups } = useGlobalSearch(query);
  const { data: targets } = useTargets();
  const currentTargetId = useWorkspaceStore((s) => s.currentTargetId);
  const startScan = useStartScan();

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((v) => !v);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    function onOpenSearch() {
      setOpen(true);
    }
    window.addEventListener(COMMAND_PALETTE_EVENT, onOpenSearch);
    return () => window.removeEventListener(COMMAND_PALETTE_EVENT, onOpenSearch);
  }, []);

  function go(href: string) {
    navigate(href);
    setOpen(false);
    setQuery("");
  }

  const currentTarget = targets?.find((t) => t.id === currentTargetId);

  return (
    <Command.Dialog
      open={open}
      onOpenChange={setOpen}
      label="Global command palette"
      shouldFilter={false}
      className="fixed left-1/2 top-24 z-50 w-full max-w-xl -translate-x-1/2 overflow-hidden rounded-lg border border-[color:var(--color-border-strong)] bg-[color:var(--color-surface-elevated)] shadow-2xl"
    >
      <div className="flex items-center gap-2 border-b border-[color:var(--color-border)] px-3">
        <SearchIcon className="size-4 text-[color:var(--color-text-faint)]" aria-hidden="true" />
        <Command.Input
          value={query}
          onValueChange={setQuery}
          placeholder={`Search ${currentTarget?.name ?? "assets, findings, investigations..."}...`}
          className="h-11 flex-1 bg-transparent text-sm text-[color:var(--color-text)] outline-none placeholder:text-[color:var(--color-text-faint)]"
        />
        <kbd className="rounded border border-[color:var(--color-border)] px-1.5 py-0.5 text-[0.65rem] text-[color:var(--color-text-faint)]">Esc</kbd>
      </div>
      <Command.List className="max-h-96 overflow-y-auto p-2">
        <Command.Empty className="px-2 py-6 text-center text-sm text-[color:var(--color-text-muted)]">
          No results found.
        </Command.Empty>

        {!query && (
          <Command.Group heading="Commands" className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:font-medium [&_[cmdk-group-heading]]:text-[color:var(--color-text-faint)]">
            {STATIC_COMMANDS.map((cmd) => (
              <Command.Item
                key={cmd.href}
                onSelect={() => go(cmd.href)}
                className="flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-2 text-sm text-[color:var(--color-text)] aria-selected:bg-[color:var(--color-surface-hover)]"
              >
                <cmd.icon className="size-4 text-[color:var(--color-text-faint)]" />
                {cmd.label}
              </Command.Item>
            ))}
            <Command.Item
              onSelect={() => {
                if (currentTargetId) {
                  startScan.mutate({ targetValue: currentTarget?.value ?? "", scanType: "http" });
                }
                setOpen(false);
              }}
              className="flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-2 text-sm text-[color:var(--color-text)] aria-selected:bg-[color:var(--color-surface-hover)]"
            >
              <Radar className="size-4 text-[color:var(--color-text-faint)]" />
              Start Scan
            </Command.Item>
          </Command.Group>
        )}

        {query &&
          groups?.map((group) => (
            <Command.Group
              key={group.entity}
              heading={`${group.label} (${group.results.length})`}
              className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:font-medium [&_[cmdk-group-heading]]:text-[color:var(--color-text-faint)]"
            >
              {group.results.map((r) => (
                <Command.Item
                  key={r.id}
                  onSelect={() => go(r.href)}
                  className="flex cursor-pointer flex-col items-start gap-0.5 rounded-md px-2 py-1.5 aria-selected:bg-[color:var(--color-surface-hover)]"
                >
                  <span className="text-sm text-[color:var(--color-text)]">{r.title}</span>
                  <span className="text-xs text-[color:var(--color-text-faint)]">{r.subtitle}</span>
                </Command.Item>
              ))}
            </Command.Group>
          ))}
      </Command.List>
    </Command.Dialog>
  );
}
