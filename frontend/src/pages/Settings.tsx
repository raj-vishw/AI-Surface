import type { ReactNode } from "react";
import { PageHeader } from "@/components/common/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { Alert } from "@/components/ui/Alert";
import { Badge } from "@/components/ui/Badge";
import { useTargets } from "@/hooks/useWorkspace";
import { useWorkspaceStore } from "@/store/workspace";
import { USE_MOCKS, API_BASE_URL } from "@/api/config";

/**
 * Spec §40: "Create settings only for actual backend capabilities... Do
 * not implement authentication settings yet." This backend has no
 * settings-write API at all (every configuration value is read from
 * `configs/*.yaml` / environment variables server-side — see
 * internal/config) — so this page is read-only, reflecting the actual
 * running configuration rather than presenting editable fields that
 * would silently do nothing when saved.
 */
export default function Settings() {
  const { data: targets } = useTargets();
  const currentTargetId = useWorkspaceStore((s) => s.currentTargetId);
  const currentTarget = targets?.find((t) => t.id === currentTargetId);

  return (
    <div>
      <PageHeader title="Settings" description="Read-only — this backend's configuration is managed via environment variables and configs/*.yaml, not this UI." />

      <div className="space-y-4 p-6">
        <Alert variant="info" title="No settings-write API exists yet">
          Every value below reflects this backend's actual configuration source
          (internal/config). Changing behavior today means editing environment
          variables or configs/&lt;environment&gt;/config.yaml server-side — see
          docs/operations/production-readiness.md.
        </Alert>

        <Card>
          <CardHeader><CardTitle>Project</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            <Row label="Name" value={currentTarget?.name ?? "—"} />
            <Row label="Target value" value={currentTarget?.value ?? "—"} mono />
            <Row label="Type" value={currentTarget?.type ?? "—"} />
            <Row label="Authorization status" value={currentTarget?.authorizationStatus ?? "—"} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Scanning</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            <Row label="HTTP discovery" value="Enabled by default (configs/defaults/config.yaml)" />
            <Row label="Network discovery" value="Enabled by default" />
            <Row label="DNS & subdomain discovery" value="Enabled by default" />
            <Row label="Endpoint & API discovery" value="Enabled by default" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Detection</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            <Row label="Mode" value="passive (default) — safe_active requires an authorized target" />
            <Row label="Rule engine" value="Enabled by default" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>AI</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            <Row label="AI assistant" value="Disabled by default — must be explicitly enabled per deployment (docs/ai/safety.md)" />
            <Row label="Default provider" value="mock (no external dependency)" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>API</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            <Row label="VITE_API_BASE_URL" value={API_BASE_URL || "(not set)"} mono />
            <Row
              label="Data source"
              value={
                <Badge className={USE_MOCKS ? "border-[color:var(--color-warning)]/30 bg-[color:var(--color-warning-muted)] text-[color:var(--color-warning)]" : "border-[color:var(--color-success)]/30 bg-[color:var(--color-success-muted)] text-[color:var(--color-success)]"}>
                  {USE_MOCKS ? "Mock data (no backend configured)" : "Live backend"}
                </Badge>
              }
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>System</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            <Row label="Backend health" value="GET /health, /live, /ready — no other REST API exists yet" mono />
            <Row label="Authentication" value="Not implemented (see src/auth/) — planned for a future phase" />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-[color:var(--color-text-faint)]">{label}</span>
      <span className={mono ? "font-technical text-[color:var(--color-text)]" : "text-right text-[color:var(--color-text)]"}>{value}</span>
    </div>
  );
}
