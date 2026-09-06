import { Outlet } from "react-router-dom";
import { Toaster } from "sonner";
import { TooltipProvider } from "@/components/ui/Tooltip";
import { Sidebar } from "./Sidebar";
import { MobileSidebar } from "./MobileSidebar";
import { Navbar } from "./Navbar";
import { CommandPalette } from "@/components/navigation/CommandPalette";

export function AppShell() {
  return (
    <TooltipProvider delayDuration={200}>
      <div className="flex h-dvh w-full overflow-hidden bg-[color:var(--color-bg)]">
        <Sidebar />
        <MobileSidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <Navbar />
          <main className="flex-1 overflow-y-auto">
            <Outlet />
          </main>
        </div>
      </div>
      <CommandPalette />
      <Toaster
        theme="dark"
        toastOptions={{
          style: {
            background: "var(--color-surface-elevated)",
            border: "1px solid var(--color-border-strong)",
            color: "var(--color-text)",
          },
        }}
      />
    </TooltipProvider>
  );
}
