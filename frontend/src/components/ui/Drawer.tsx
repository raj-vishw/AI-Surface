import type { ComponentPropsWithoutRef } from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";

/** A side-sheet built on Radix's Dialog primitive (there is no separate
 * "Drawer" primitive in Radix) — used for quick-inspection panels (spec
 * §58), e.g. clicking an asset/finding row without leaving the list. */
export const Drawer = DialogPrimitive.Root;
export const DrawerTrigger = DialogPrimitive.Trigger;

export function DrawerContent({
  className,
  children,
  ...props
}: ComponentPropsWithoutRef<typeof DialogPrimitive.Content>) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/60" />
      <DialogPrimitive.Content
        className={cn(
          "fixed right-0 top-0 z-50 h-dvh w-full max-w-md overflow-y-auto border-l border-[color:var(--color-border-strong)] bg-[color:var(--color-surface-elevated)] p-5 shadow-2xl",
          className,
        )}
        {...props}
      >
        {children}
        <DialogPrimitive.Close className="absolute right-4 top-4 rounded-sm text-[color:var(--color-text-muted)] hover:text-[color:var(--color-text)]">
          <X className="size-4" />
          <span className="sr-only">Close</span>
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  );
}

export const DrawerTitle = DialogPrimitive.Title;
export const DrawerDescription = DialogPrimitive.Description;
