import { create } from "zustand";
import { persist } from "zustand/middleware";

/**
 * Central workspace state (spec §54): the current target/project is
 * globally available here, and every query hook (see hooks/*.ts) reads
 * it from this one store rather than each component tracking its own
 * copy — this is what prevents "project-context leakage" (spec §54)
 * across pages. Sidebar collapse state lives alongside it since it's the
 * other piece of cross-page UI state the shell needs.
 */
interface WorkspaceState {
  currentTargetId: string | null;
  setCurrentTargetId: (id: string) => void;

  sidebarCollapsed: boolean;
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;

  mobileSidebarOpen: boolean;
  setMobileSidebarOpen: (open: boolean) => void;
}

export const useWorkspaceStore = create<WorkspaceState>()(
  persist(
    (set) => ({
      currentTargetId: null,
      setCurrentTargetId: (id) => set({ currentTargetId: id }),

      sidebarCollapsed: false,
      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
      setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),

      mobileSidebarOpen: false,
      setMobileSidebarOpen: (open) => set({ mobileSidebarOpen: open }),
    }),
    {
      name: "ai-recon-workspace",
      partialize: (s) => ({ currentTargetId: s.currentTargetId, sidebarCollapsed: s.sidebarCollapsed }),
    },
  ),
);
