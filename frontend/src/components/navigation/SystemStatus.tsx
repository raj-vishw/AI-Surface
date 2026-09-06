import { useQuery } from "@tanstack/react-query";
import { Circle } from "lucide-react";
import { USE_MOCKS, API_BASE_URL } from "@/api/config";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/Tooltip";

async function checkHealth(): Promise<"ok" | "unreachable"> {
  try {
    const res = await fetch(`${API_BASE_URL.replace(/\/$/, "")}/health`, { signal: AbortSignal.timeout(4000) });
    return res.ok ? "ok" : "unreachable";
  } catch {
    return "unreachable";
  }
}

/** Reflects this backend's real /health endpoint (internal/httpserver) —
 * when running against mock data (the default — see src/api/config.ts),
 * this shows that plainly rather than pretending a health check
 * succeeded against a backend that was never called. */
export function SystemStatus() {
  const { data: status } = useQuery({
    queryKey: ["system-health"],
    queryFn: checkHealth,
    enabled: !USE_MOCKS,
    refetchInterval: 30_000,
  });

  if (USE_MOCKS) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="flex items-center gap-1.5 rounded-full border border-[color:var(--color-warning)]/30 bg-[color:var(--color-warning-muted)] px-2 py-1 text-xs font-medium text-[color:var(--color-warning)]">
            <Circle className="size-2 fill-current" />
            Demo data
          </span>
        </TooltipTrigger>
        <TooltipContent>
          No backend API is configured (VITE_API_BASE_URL) — showing realistic mock data instead of live results.
        </TooltipContent>
      </Tooltip>
    );
  }

  const ok = status === "ok";
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className={`flex items-center gap-1.5 rounded-full border px-2 py-1 text-xs font-medium ${
            ok
              ? "border-[color:var(--color-success)]/30 bg-[color:var(--color-success-muted)] text-[color:var(--color-success)]"
              : "border-[color:var(--color-danger)]/30 bg-[color:var(--color-danger-muted)] text-[color:var(--color-danger)]"
          }`}
        >
          <Circle className="size-2 fill-current" />
          {ok ? "Operational" : "Unreachable"}
        </span>
      </TooltipTrigger>
      <TooltipContent>Backend GET /health: {ok ? "200 OK" : "unreachable"}</TooltipContent>
    </Tooltip>
  );
}
