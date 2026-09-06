import type { ComponentPropsWithoutRef } from "react";
import * as TabsPrimitive from "@radix-ui/react-tabs";
import { cn } from "@/lib/utils";

export const Tabs = TabsPrimitive.Root;

export function TabsList({ className, ...props }: ComponentPropsWithoutRef<typeof TabsPrimitive.List>) {
  return (
    <TabsPrimitive.List
      className={cn(
        "inline-flex items-center gap-1 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-1",
        className,
      )}
      {...props}
    />
  );
}

export function TabsTrigger({ className, ...props }: ComponentPropsWithoutRef<typeof TabsPrimitive.Trigger>) {
  return (
    <TabsPrimitive.Trigger
      className={cn(
        "rounded-sm px-3 py-1.5 text-sm font-medium text-[color:var(--color-text-muted)] transition-colors data-[state=active]:bg-[color:var(--color-surface-elevated)] data-[state=active]:text-[color:var(--color-text)]",
        className,
      )}
      {...props}
    />
  );
}

export function TabsContent({ className, ...props }: ComponentPropsWithoutRef<typeof TabsPrimitive.Content>) {
  return <TabsPrimitive.Content className={cn("mt-4 focus-visible:outline-none", className)} {...props} />;
}
