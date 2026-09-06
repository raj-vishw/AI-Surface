import type { ComponentPropsWithoutRef } from "react";
import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import { cn } from "@/lib/utils";

export const TooltipProvider = TooltipPrimitive.Provider;
export const Tooltip = TooltipPrimitive.Root;
export const TooltipTrigger = TooltipPrimitive.Trigger;

export function TooltipContent({ className, sideOffset = 6, ...props }: ComponentPropsWithoutRef<typeof TooltipPrimitive.Content>) {
  return (
    <TooltipPrimitive.Portal>
      <TooltipPrimitive.Content
        sideOffset={sideOffset}
        className={cn(
          "z-50 max-w-xs rounded-md border border-[color:var(--color-border-strong)] bg-[color:var(--color-surface-elevated)] px-2.5 py-1.5 text-xs text-[color:var(--color-text)] shadow-lg",
          className,
        )}
        {...props}
      />
    </TooltipPrimitive.Portal>
  );
}
