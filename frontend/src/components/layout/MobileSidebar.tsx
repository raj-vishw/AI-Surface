import * as DialogPrimitive from "@radix-ui/react-dialog";
import { useWorkspaceStore } from "@/store/workspace";
import { SidebarContent } from "./Sidebar";

export function MobileSidebar() {
  const open = useWorkspaceStore((s) => s.mobileSidebarOpen);
  const setOpen = useWorkspaceStore((s) => s.setMobileSidebarOpen);

  return (
    <DialogPrimitive.Root open={open} onOpenChange={setOpen}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/60 md:hidden" />
        <DialogPrimitive.Content
          className="fixed left-0 top-0 z-40 h-dvh w-64 border-r border-[color:var(--color-border)] bg-[color:var(--color-bg)] md:hidden"
          aria-describedby={undefined}
        >
          <DialogPrimitive.Title className="sr-only">Navigation</DialogPrimitive.Title>
          <SidebarContent collapsed={false} />
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}
