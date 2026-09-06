import { AlertOctagon, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { HttpError } from "@/api/client";

interface ErrorStateProps {
  error: unknown;
  onRetry?: () => void;
  className?: string;
}

/** Useful error states (spec §47): what failed, whether retry is
 * possible, a retry button — never a raw stack trace. HttpError's
 * message is already the backend's own safe, category-scoped message
 * (see internal/errors.Error.ClientMessage's backend-side equivalent);
 * anything else is shown as a generic message rather than risking a
 * leaked internal detail. */
export function ErrorState({ error, onRetry, className }: ErrorStateProps) {
  const message = error instanceof HttpError ? error.message : "Something went wrong loading this data.";
  return (
    <div className={`flex flex-col items-center justify-center gap-3 px-6 py-14 text-center ${className ?? ""}`}>
      <div className="flex size-11 items-center justify-center rounded-full bg-[color:var(--color-danger-muted)] border border-[color:var(--color-danger)]/30">
        <AlertOctagon className="size-5 text-[color:var(--color-danger)]" aria-hidden="true" />
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium text-[color:var(--color-text)]">Couldn't load this data</p>
        <p className="max-w-sm text-sm text-[color:var(--color-text-muted)]">{message}</p>
      </div>
      {onRetry && (
        <Button variant="secondary" size="sm" onClick={onRetry}>
          <RefreshCw className="size-3.5" /> Retry
        </Button>
      )}
    </div>
  );
}
