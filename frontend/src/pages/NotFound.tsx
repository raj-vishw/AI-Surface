import { Link } from "react-router-dom";
import { ShieldQuestion } from "lucide-react";

export default function NotFound() {
  return (
    <div className="flex h-dvh flex-col items-center justify-center gap-3 bg-[color:var(--color-bg)] text-center">
      <ShieldQuestion className="size-10 text-[color:var(--color-text-faint)]" />
      <p className="text-lg font-semibold text-[color:var(--color-text)]">Page not found</p>
      <p className="max-w-xs text-sm text-[color:var(--color-text-muted)]">The page you're looking for doesn't exist or has moved.</p>
      <Link to="/dashboard" className="mt-2 rounded-md bg-[color:var(--color-accent)] px-4 py-2 text-sm font-semibold text-black">
        Go to Dashboard
      </Link>
    </div>
  );
}
