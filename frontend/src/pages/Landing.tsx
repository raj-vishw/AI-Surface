import { Link } from "react-router-dom";
import { ArrowRight, Radar, ShieldHalf, Search, BrainCircuit, FileCheck2 } from "lucide-react";
import { AttackSurfaceDiagram } from "@/components/dashboard/AttackSurfaceDiagram";

const CAPABILITIES = [
  { icon: Radar, title: "Discover", body: "Map domains, subdomains, IPs, services, and endpoints as they actually exist today." },
  { icon: ShieldHalf, title: "Assess", body: "Detect findings, score risk, and surface what changed since the last scan." },
  { icon: Search, title: "Investigate", body: "Correlate activity into attack chains and work cases end to end with a full timeline." },
  { icon: BrainCircuit, title: "Analyze", body: "AI-assisted summaries and next steps, every claim traceable to real evidence." },
  { icon: FileCheck2, title: "Report", body: "Versioned, citation-checked reports and hashed evidence packages, on demand." },
];

export default function Landing() {
  return (
    <div className="min-h-dvh bg-[color:var(--color-bg)]">
      <header className="flex items-center justify-between px-6 py-5 sm:px-10">
        <div className="flex items-center gap-2">
          <div className="flex size-8 items-center justify-center rounded-md bg-[color:var(--color-accent-muted)]">
            <ShieldHalf className="size-4 text-[color:var(--color-accent)]" />
          </div>
          <span className="text-sm font-bold tracking-tight text-[color:var(--color-text)]">AI-RECON</span>
        </div>
        <Link
          to="/dashboard"
          className="rounded-md border border-[color:var(--color-border-strong)] px-3.5 py-1.5 text-sm font-medium text-[color:var(--color-text)] hover:bg-[color:var(--color-surface-hover)]"
        >
          Open Dashboard
        </Link>
      </header>

      <main className="mx-auto max-w-5xl px-6 pb-24 pt-10 sm:px-10 sm:pt-16">
        <div className="max-w-2xl">
          <p className="mb-3 inline-flex items-center gap-1.5 rounded-full border border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-2.5 py-1 text-xs font-medium text-[color:var(--color-text-muted)]">
            <span className="size-1.5 rounded-full bg-[color:var(--color-success)]" />
            Security workspace
          </p>
          <h1 className="text-4xl font-extrabold tracking-tight text-[color:var(--color-text)] sm:text-5xl">AI-RECON</h1>
          <p className="mt-4 text-lg text-[color:var(--color-text-muted)]">
            Security reconnaissance and investigation, unified into one platform.
          </p>
          <p className="mt-3 max-w-xl text-sm leading-relaxed text-[color:var(--color-text-muted)]">
            Discover assets, understand exposure, investigate security events, correlate
            activity, and use AI-assisted analysis — from a single security workspace.
          </p>

          <div className="mt-8 flex flex-wrap items-center gap-3">
            <Link
              to="/dashboard"
              className="inline-flex items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-4 py-2.5 text-sm font-semibold text-black hover:bg-[color:var(--color-accent-strong)]"
            >
              Open Dashboard <ArrowRight className="size-4" />
            </Link>
            <Link
              to="/reconnaissance"
              className="inline-flex items-center gap-2 rounded-md border border-[color:var(--color-border-strong)] px-4 py-2.5 text-sm font-medium text-[color:var(--color-text)] hover:bg-[color:var(--color-surface-hover)]"
            >
              Explore Reconnaissance
            </Link>
          </div>
        </div>

        <div className="mt-14 overflow-hidden rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)]">
          <div className="border-b border-[color:var(--color-border)] px-4 py-3">
            <p className="text-xs font-medium uppercase tracking-wide text-[color:var(--color-text-faint)]">
              Attack surface — discovery pipeline
            </p>
          </div>
          <AttackSurfaceDiagram />
        </div>

        <div className="mt-16 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
          {CAPABILITIES.map((c) => (
            <div key={c.title} className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-4">
              <c.icon className="size-5 text-[color:var(--color-accent)]" />
              <p className="mt-3 text-sm font-semibold text-[color:var(--color-text)]">{c.title}</p>
              <p className="mt-1 text-xs leading-relaxed text-[color:var(--color-text-muted)]">{c.body}</p>
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}
