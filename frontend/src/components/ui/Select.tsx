import type { ComponentPropsWithoutRef } from "react";
import * as SelectPrimitive from "@radix-ui/react-select";
import { Check, ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";

export const Select = SelectPrimitive.Root;
export const SelectValue = SelectPrimitive.Value;
export const SelectGroup = SelectPrimitive.Group;

export function SelectTrigger({ className, children, ...props }: ComponentPropsWithoutRef<typeof SelectPrimitive.Trigger>) {
  return (
    <SelectPrimitive.Trigger
      className={cn(
        "flex h-9 w-full items-center justify-between gap-2 rounded-md border border-[color:var(--color-border-strong)] bg-[color:var(--color-surface)] px-3 py-1 text-sm text-[color:var(--color-text)] outline-none focus-visible:border-[color:var(--color-accent)] disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
      {...props}
    >
      {children}
      <SelectPrimitive.Icon asChild>
        <ChevronDown className="size-4 text-[color:var(--color-text-faint)]" />
      </SelectPrimitive.Icon>
    </SelectPrimitive.Trigger>
  );
}

export function SelectContent({ className, children, position = "popper", ...props }: ComponentPropsWithoutRef<typeof SelectPrimitive.Content>) {
  return (
    <SelectPrimitive.Portal>
      <SelectPrimitive.Content
        position={position}
        className={cn(
          "z-50 min-w-[8rem] overflow-hidden rounded-md border border-[color:var(--color-border-strong)] bg-[color:var(--color-surface-elevated)] shadow-xl",
          position === "popper" && "translate-y-1",
          className,
        )}
        {...props}
      >
        <SelectPrimitive.Viewport className="p-1">{children}</SelectPrimitive.Viewport>
      </SelectPrimitive.Content>
    </SelectPrimitive.Portal>
  );
}

export function SelectItem({ className, children, ...props }: ComponentPropsWithoutRef<typeof SelectPrimitive.Item>) {
  return (
    <SelectPrimitive.Item
      className={cn(
        "relative flex cursor-pointer select-none items-center rounded-sm py-1.5 pl-7 pr-2 text-sm text-[color:var(--color-text)] outline-none data-[highlighted]:bg-[color:var(--color-surface-hover)]",
        className,
      )}
      {...props}
    >
      <span className="absolute left-2 flex size-3.5 items-center justify-center">
        <SelectPrimitive.ItemIndicator>
          <Check className="size-3.5" />
        </SelectPrimitive.ItemIndicator>
      </span>
      <SelectPrimitive.ItemText>{children}</SelectPrimitive.ItemText>
    </SelectPrimitive.Item>
  );
}

export function SelectLabel({ className, ...props }: ComponentPropsWithoutRef<typeof SelectPrimitive.Label>) {
  return <SelectPrimitive.Label className={cn("px-2 py-1.5 text-xs font-medium text-[color:var(--color-text-faint)]", className)} {...props} />;
}

export function SelectSeparator({ className, ...props }: ComponentPropsWithoutRef<typeof SelectPrimitive.Separator>) {
  return <SelectPrimitive.Separator className={cn("my-1 h-px bg-[color:var(--color-border)]", className)} {...props} />;
}
