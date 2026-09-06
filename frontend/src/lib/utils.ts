import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** Merge Tailwind class lists, resolving conflicting utilities (the
 * standard shadcn/ui `cn` helper). */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Format a timestamp for display. Full form: "2026-03-14 09:22:10 UTC". */
export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return (
    d.toISOString().slice(0, 19).replace("T", " ") + " UTC"
  );
}

/** Format a relative "time ago" string for compact display. */
export function formatRelativeTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  const diffMs = Date.now() - d.getTime();
  const diffSec = Math.round(diffMs / 1000);
  const abs = Math.abs(diffSec);
  if (abs < 60) return "just now";
  if (abs < 3600) return `${Math.round(abs / 60)}m ago`;
  if (abs < 86400) return `${Math.round(abs / 3600)}h ago`;
  if (abs < 86400 * 30) return `${Math.round(abs / 86400)}d ago`;
  return `${Math.round(abs / (86400 * 30))}mo ago`;
}

/** Truncate a UUID/hash for compact display, e.g. "3fae21a0…8c9d". */
export function truncateId(id: string, head = 8, tail = 4): string {
  if (id.length <= head + tail + 1) return id;
  return `${id.slice(0, head)}…${id.slice(-tail)}`;
}

/** Format a byte count for human display. */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / 1024 ** i).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/** Debounce a callback by delayMs — used for search inputs (spec §60). */
export function debounce<Args extends unknown[]>(
  fn: (...args: Args) => void,
  delayMs: number,
): (...args: Args) => void {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return (...args: Args) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delayMs);
  };
}
