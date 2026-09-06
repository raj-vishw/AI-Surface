import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { useWorkspaceStore } from "@/store/workspace";
import { listTargets } from "@/api/targets";

/** Loads the target list and ensures a current target is always selected
 * once targets exist — the single place project-context initialization
 * happens (spec §54). */
export function useTargets() {
  const query = useQuery({ queryKey: ["targets"], queryFn: listTargets, staleTime: 60_000 });
  const currentTargetId = useWorkspaceStore((s) => s.currentTargetId);
  const setCurrentTargetId = useWorkspaceStore((s) => s.setCurrentTargetId);

  useEffect(() => {
    if (!query.data || query.data.length === 0) return;
    const stillValid = query.data.some((t) => t.id === currentTargetId);
    if (!currentTargetId || !stillValid) {
      setCurrentTargetId(query.data[0].id);
    }
  }, [query.data, currentTargetId, setCurrentTargetId]);

  return query;
}

/** The one hook every scoped query hook builds on — never call
 * useWorkspaceStore((s) => s.currentTargetId) directly elsewhere, so
 * there is exactly one place "which target am I scoped to" is read. */
export function useCurrentTargetId(): string | null {
  return useWorkspaceStore((s) => s.currentTargetId);
}
