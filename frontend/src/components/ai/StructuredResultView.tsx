import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Eye, Sparkles, HelpCircle, ArrowRight } from "lucide-react";
import type { AIStructuredResult } from "@/types/ai";
import { parseCitation } from "@/types/ai";

const CITATION_HREF: Record<string, (id: string) => string> = {
  finding: (id) => `/findings/${id}`,
  asset: (id) => `/assets/${id}`,
  investigation: (id) => `/investigations/${id}`,
  correlation: () => `/attack-chains`,
  alert: () => `/alerts`,
};

/** Renders one line of Observed/Inferred text, turning every citation
 * token into a link straight to its underlying evidence (spec §31:
 * "When evidence exists: link directly to the underlying evidence"). */
function CitedLine({ text }: { text: string }) {
  const parts = text.split(/(\[[a-z_]+:[^\]]+\])/g);
  return (
    <p className="text-sm leading-relaxed text-[color:var(--color-text)]">
      {parts.map((part, i) => {
        const parsed = parseCitation(part);
        if (!parsed) return <span key={i}>{part}</span>;
        const hrefFn = CITATION_HREF[parsed.entityType];
        if (!hrefFn) {
          return (
            <span key={i} className="font-technical text-xs text-[color:var(--color-text-faint)]">
              {part}
            </span>
          );
        }
        return (
          <Link
            key={i}
            to={hrefFn(parsed.entityId)}
            className="mx-0.5 inline-flex items-center gap-0.5 rounded border border-[color:var(--color-accent)]/30 bg-[color:var(--color-accent-muted)] px-1 py-0.5 font-technical text-[0.7rem] text-[color:var(--color-accent-strong)] hover:bg-[color:var(--color-accent)]/25"
          >
            {parsed.entityType}
          </Link>
        );
      })}
    </p>
  );
}

/**
 * The AI Trust UI (spec §31) — this is not a UI invention layered over
 * free-form text. It renders internal/ai.StructuredResult's real,
 * deterministic sections directly: Observed states only what the
 * platform's own records show; Inferred is a derived interpretation,
 * never asserted as fact; Unknown + Evidence Gaps make uncertainty
 * explicit; Next Steps is the recommendation. Nothing here presents an
 * AI-generated statement as a confirmed fact.
 */
export function StructuredResultView({ result }: { result: AIStructuredResult }) {
  return (
    <div className="space-y-5">
      <div>
        <p className="text-sm leading-relaxed text-[color:var(--color-text)]">{result.summary}</p>
      </div>

      <Section icon={Eye} title="Evidence — Observed" tone="text-[color:var(--color-success)]" empty="Nothing directly observed yet.">
        {result.observed.map((line, i) => (
          <CitedLine key={i} text={line} />
        ))}
      </Section>

      <Section icon={Sparkles} title="AI Analysis — Inferred" tone="text-[color:var(--color-accent)]" empty="No inferences drawn yet.">
        {result.inferred.map((line, i) => (
          <CitedLine key={i} text={line} />
        ))}
      </Section>

      <Section icon={HelpCircle} title="Uncertainty — Unknown & Evidence Gaps" tone="text-[color:var(--color-warning)]" empty="No gaps recorded.">
        {[...result.unknown, ...result.evidenceGaps].map((line, i) => (
          <p key={i} className="text-sm text-[color:var(--color-text-muted)]">{line}</p>
        ))}
      </Section>

      <Section icon={ArrowRight} title="Recommendation — Next Steps" tone="text-[color:var(--color-info)]" empty="No next steps suggested.">
        <ul className="space-y-1.5">
          {result.nextSteps.map((step, i) => (
            <li key={i} className="flex items-start gap-2 text-sm text-[color:var(--color-text)]">
              <ArrowRight className="mt-0.5 size-3.5 shrink-0 text-[color:var(--color-info)]" />
              {step}
            </li>
          ))}
        </ul>
      </Section>

      {result.questions.length > 0 && (
        <Section icon={HelpCircle} title="Open questions" tone="text-[color:var(--color-text-faint)]" empty="">
          <ul className="space-y-1">
            {result.questions.map((q, i) => (
              <li key={i} className="text-sm italic text-[color:var(--color-text-muted)]">{q}</li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}

function Section({
  icon: Icon,
  title,
  tone,
  empty,
  children,
}: {
  icon: typeof Eye;
  title: string;
  tone: string;
  empty: string;
  children: ReactNode;
}) {
  const isEmptyArray = Array.isArray(children) && children.length === 0;
  return (
    <div>
      <p className={`mb-1.5 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide ${tone}`}>
        <Icon className="size-3.5" /> {title}
      </p>
      {isEmptyArray ? <p className="text-sm text-[color:var(--color-text-faint)]">{empty}</p> : <div className="space-y-1.5">{children}</div>}
    </div>
  );
}
