import { forwardRef, type InputHTMLAttributes, type LabelHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, type, ...props }, ref) => (
    <input
      type={type}
      ref={ref}
      className={cn(
        "flex h-9 w-full rounded-md border border-[color:var(--color-border-strong)] bg-[color:var(--color-surface)] px-3 py-1 text-sm text-[color:var(--color-text)] placeholder:text-[color:var(--color-text-faint)] outline-none transition-colors focus-visible:border-[color:var(--color-accent)] disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
      {...props}
    />
  ),
);
Input.displayName = "Input";

export const Label = forwardRef<HTMLLabelElement, LabelHTMLAttributes<HTMLLabelElement>>(
  ({ className, ...props }, ref) => (
    <label ref={ref} className={cn("text-xs font-medium text-[color:var(--color-text-muted)]", className)} {...props} />
  ),
);
Label.displayName = "Label";
