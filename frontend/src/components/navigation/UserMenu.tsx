import { UserCircle2 } from "lucide-react";
import { useAuth } from "@/auth/useAuth";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/DropdownMenu";

/** Spec §8: "use a simple 'Analyst' placeholder... do not create
 * authentication logic." See src/auth/useAuth.ts for the swap-in point
 * a real auth provider will use later. */
export function UserMenu() {
  const { user } = useAuth();
  return (
    <DropdownMenu>
      <DropdownMenuTrigger className="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-[color:var(--color-surface-hover)] focus-visible:outline-none">
        <UserCircle2 className="size-5 text-[color:var(--color-text-muted)]" aria-hidden="true" />
        <span className="hidden text-[color:var(--color-text)] sm:inline">{user.displayName}</span>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-48">
        <DropdownMenuLabel>{user.displayName}</DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem disabled>Profile (not yet available)</DropdownMenuItem>
        <DropdownMenuItem disabled>Sign out (authentication not yet implemented)</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
