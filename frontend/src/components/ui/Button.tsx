import { forwardRef, type ButtonHTMLAttributes } from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default:
          "bg-[color:var(--color-accent)] text-black hover:bg-[color:var(--color-accent-strong)]",
        secondary:
          "bg-[color:var(--color-surface-elevated)] text-[color:var(--color-text)] border border-[color:var(--color-border-strong)] hover:bg-[color:var(--color-surface-hover)]",
        outline:
          "border border-[color:var(--color-border-strong)] bg-transparent hover:bg-[color:var(--color-surface-hover)] text-[color:var(--color-text)]",
        ghost: "hover:bg-[color:var(--color-surface-hover)] text-[color:var(--color-text)]",
        danger: "bg-[color:var(--color-danger)] text-white hover:opacity-90",
        link: "text-[color:var(--color-accent)] underline-offset-4 hover:underline",
      },
      size: {
        default: "h-9 px-3.5",
        sm: "h-8 px-2.5 text-xs",
        lg: "h-10 px-5",
        icon: "size-9",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
);

export interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return <Comp className={cn(buttonVariants({ variant, size }), className)} ref={ref} {...props} />;
  },
);
Button.displayName = "Button";
