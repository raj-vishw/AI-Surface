import type { ComponentPropsWithoutRef } from "react";
import * as DropdownPrimitive from "@radix-ui/react-dropdown-menu";
import { Check, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";

export const DropdownMenu = DropdownPrimitive.Root;
export const DropdownMenuTrigger = DropdownPrimitive.Trigger;
export const DropdownMenuGroup = DropdownPrimitive.Group;
export const DropdownMenuSub = DropdownPrimitive.Sub;
export const DropdownMenuRadioGroup = DropdownPrimitive.RadioGroup;

export function DropdownMenuContent({ className, sideOffset = 6, ...props }: ComponentPropsWithoutRef<typeof DropdownPrimitive.Content>) {
  return (
    <DropdownPrimitive.Portal>
      <DropdownPrimitive.Content
        sideOffset={sideOffset}
        className={cn(
          "z-50 min-w-[10rem] overflow-hidden rounded-md border border-[color:var(--color-border-strong)] bg-[color:var(--color-surface-elevated)] p-1 shadow-xl",
          className,
        )}
        {...props}
      />
    </DropdownPrimitive.Portal>
  );
}

export function DropdownMenuItem({ className, ...props }: ComponentPropsWithoutRef<typeof DropdownPrimitive.Item>) {
  return (
    <DropdownPrimitive.Item
      className={cn(
        "flex cursor-pointer select-none items-center gap-2 rounded-sm px-2 py-1.5 text-sm text-[color:var(--color-text)] outline-none data-[highlighted]:bg-[color:var(--color-surface-hover)] data-[disabled]:opacity-50",
        className,
      )}
      {...props}
    />
  );
}

export function DropdownMenuCheckboxItem({ className, children, checked, ...props }: ComponentPropsWithoutRef<typeof DropdownPrimitive.CheckboxItem>) {
  return (
    <DropdownPrimitive.CheckboxItem
      checked={checked}
      className={cn(
        "flex cursor-pointer select-none items-center gap-2 rounded-sm py-1.5 pl-7 pr-2 text-sm text-[color:var(--color-text)] outline-none data-[highlighted]:bg-[color:var(--color-surface-hover)]",
        className,
      )}
      {...props}
    >
      <span className="absolute left-2 flex size-3.5 items-center justify-center">
        <DropdownPrimitive.ItemIndicator>
          <Check className="size-3.5" />
        </DropdownPrimitive.ItemIndicator>
      </span>
      {children}
    </DropdownPrimitive.CheckboxItem>
  );
}

export function DropdownMenuLabel({ className, ...props }: ComponentPropsWithoutRef<typeof DropdownPrimitive.Label>) {
  return <DropdownPrimitive.Label className={cn("px-2 py-1.5 text-xs font-medium text-[color:var(--color-text-faint)]", className)} {...props} />;
}

export function DropdownMenuSeparator({ className, ...props }: ComponentPropsWithoutRef<typeof DropdownPrimitive.Separator>) {
  return <DropdownPrimitive.Separator className={cn("my-1 h-px bg-[color:var(--color-border)]", className)} {...props} />;
}

export function DropdownMenuSubTrigger({ className, children, ...props }: ComponentPropsWithoutRef<typeof DropdownPrimitive.SubTrigger>) {
  return (
    <DropdownPrimitive.SubTrigger
      className={cn(
        "flex cursor-pointer select-none items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-none data-[highlighted]:bg-[color:var(--color-surface-hover)]",
        className,
      )}
      {...props}
    >
      {children}
      <ChevronRight className="ml-auto size-3.5" />
    </DropdownPrimitive.SubTrigger>
  );
}

export function DropdownMenuSubContent({ className, ...props }: ComponentPropsWithoutRef<typeof DropdownPrimitive.SubContent>) {
  return (
    <DropdownPrimitive.SubContent
      className={cn("z-50 min-w-[8rem] overflow-hidden rounded-md border border-[color:var(--color-border-strong)] bg-[color:var(--color-surface-elevated)] p-1 shadow-xl", className)}
      {...props}
    />
  );
}
