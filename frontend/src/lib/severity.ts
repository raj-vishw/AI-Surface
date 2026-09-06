/**
 * Central severity/status/confidence token map — the ONE place these are
 * defined (spec §5: "Do not use random colors in individual components.
 * Define the design tokens centrally.") Every badge/chart/indicator in
 * the app imports from here rather than choosing its own color.
 *
 * Severity values mirror the backend's own vocabulary exactly
 * (internal/domain/finding.Severity, internal/domain/rule.Severity,
 * internal/domain/correlation.Severity, internal/domain/investigation.
 * Severity all use the same 5-level "informational|low|medium|high|
 * critical" scale) — this file does not invent a different scale.
 */

export type Severity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "informational";

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
];

export interface SeverityStyle {
  label: string;
  /** Tailwind text color utility */
  text: string;
  /** Tailwind background color utility (muted/translucent) */
  bg: string;
  /** Tailwind border color utility */
  border: string;
  /** Raw color token, for chart fills (Recharts/React Flow need a raw value) */
  raw: string;
}

export const SEVERITY_STYLES: Record<Severity, SeverityStyle> = {
  critical: {
    label: "Critical",
    text: "text-[color:var(--color-severity-critical)]",
    bg: "bg-[color:var(--color-severity-critical-muted)]",
    border: "border-[color:var(--color-severity-critical)]/30",
    raw: "var(--color-severity-critical)",
  },
  high: {
    label: "High",
    text: "text-[color:var(--color-severity-high)]",
    bg: "bg-[color:var(--color-severity-high-muted)]",
    border: "border-[color:var(--color-severity-high)]/30",
    raw: "var(--color-severity-high)",
  },
  medium: {
    label: "Medium",
    text: "text-[color:var(--color-severity-medium)]",
    bg: "bg-[color:var(--color-severity-medium-muted)]",
    border: "border-[color:var(--color-severity-medium)]/30",
    raw: "var(--color-severity-medium)",
  },
  low: {
    label: "Low",
    text: "text-[color:var(--color-severity-low)]",
    bg: "bg-[color:var(--color-severity-low-muted)]",
    border: "border-[color:var(--color-severity-low)]/30",
    raw: "var(--color-severity-low)",
  },
  informational: {
    label: "Info",
    text: "text-[color:var(--color-severity-info)]",
    bg: "bg-[color:var(--color-severity-info-muted)]",
    border: "border-[color:var(--color-severity-info)]/30",
    raw: "var(--color-severity-info)",
  },
};

/** Normalizes a possibly-uppercase/unexpected backend value to a known
 * Severity, defaulting to "informational" rather than throwing — a
 * dashboard must never crash on an unrecognized value from evolving
 * backend data. */
export function normalizeSeverity(value: string | null | undefined): Severity {
  const v = (value ?? "").toLowerCase();
  if (v === "critical" || v === "high" || v === "medium" || v === "low" || v === "informational") {
    return v;
  }
  return "informational";
}

// ---------------------------------------------------------------------
// Status (generic open/closed/lifecycle states across findings, alerts,
// matches, investigations, correlations, attack chains, reports)
// ---------------------------------------------------------------------

export type StatusTone = "active" | "success" | "warning" | "danger" | "inactive" | "info";

export interface StatusStyle {
  label: string;
  tone: StatusTone;
  text: string;
  bg: string;
}

const TONE_STYLES: Record<StatusTone, { text: string; bg: string }> = {
  active: { text: "text-[color:var(--color-accent-strong)]", bg: "bg-[color:var(--color-accent-muted)]" },
  success: { text: "text-[color:var(--color-success)]", bg: "bg-[color:var(--color-success-muted)]" },
  warning: { text: "text-[color:var(--color-warning)]", bg: "bg-[color:var(--color-warning-muted)]" },
  danger: { text: "text-[color:var(--color-danger)]", bg: "bg-[color:var(--color-danger-muted)]" },
  inactive: { text: "text-[color:var(--color-text-faint)]", bg: "bg-white/5" },
  info: { text: "text-[color:var(--color-info)]", bg: "bg-[color:var(--color-info-muted)]" },
};

/** Maps every status string this backend actually produces to a display
 * style. Unrecognized values fall back to a neutral "inactive" style
 * rather than guessing. */
const STATUS_MAP: Record<string, { label: string; tone: StatusTone }> = {
  // Finding / detection match status
  open: { label: "Open", tone: "danger" },
  acknowledged: { label: "Acknowledged", tone: "warning" },
  resolved: { label: "Resolved", tone: "success" },
  suppressed: { label: "Suppressed", tone: "inactive" },
  false_positive: { label: "False Positive", tone: "inactive" },
  // Alert status
  investigating: { label: "Investigating", tone: "active" },
  // Asset status
  discovered: { label: "Discovered", tone: "info" },
  active: { label: "Active", tone: "success" },
  inactive: { label: "Inactive", tone: "inactive" },
  unknown: { label: "Unknown", tone: "inactive" },
  retired: { label: "Retired", tone: "inactive" },
  // Investigation status
  new: { label: "New", tone: "info" },
  closed: { label: "Closed", tone: "inactive" },
  reopened: { label: "Reopened", tone: "warning" },
  // Correlation / attack chain status
  candidate: { label: "Candidate", tone: "warning" },
  confirmed: { label: "Confirmed", tone: "danger" },
  dismissed: { label: "Dismissed", tone: "inactive" },
  merged: { label: "Merged", tone: "inactive" },
  // Rule status
  draft: { label: "Draft", tone: "inactive" },
  enabled: { label: "Enabled", tone: "success" },
  disabled: { label: "Disabled", tone: "inactive" },
  deprecated: { label: "Deprecated", tone: "inactive" },
  // Report status
  generated: { label: "Generated", tone: "info" },
  reviewed: { label: "Reviewed", tone: "warning" },
  approved: { label: "Approved", tone: "success" },
  // Incident cluster status
  suggested: { label: "Suggested", tone: "warning" },
  accepted: { label: "Accepted", tone: "success" },
  rejected: { label: "Rejected", tone: "inactive" },
  // Scan status (this platform's scans run synchronously today — see
  // mocks/scans.ts's doc comment — these values anticipate a future
  // async execution model)
  queued: { label: "Queued", tone: "inactive" },
  running: { label: "Running", tone: "active" },
  completed: { label: "Completed", tone: "success" },
  failed: { label: "Failed", tone: "danger" },
  cancelled: { label: "Cancelled", tone: "inactive" },
};

export function statusStyle(status: string | null | undefined): StatusStyle {
  const key = (status ?? "").toLowerCase();
  const entry = STATUS_MAP[key] ?? { label: status ?? "Unknown", tone: "inactive" as StatusTone };
  const { text, bg } = TONE_STYLES[entry.tone];
  return { label: entry.label, tone: entry.tone, text, bg };
}

// ---------------------------------------------------------------------
// Confidence (asset.Confidence buckets, intelligence.Confidence, ai.Confidence)
// ---------------------------------------------------------------------

export type ConfidenceLevel = "confirmed" | "high" | "medium" | "low" | "unknown";

export function normalizeConfidence(value: string | null | undefined): ConfidenceLevel {
  const v = (value ?? "").toLowerCase();
  if (v === "confirmed" || v === "high" || v === "medium" || v === "low") return v;
  return "unknown";
}

export const CONFIDENCE_LABEL: Record<ConfidenceLevel, string> = {
  confirmed: "Confirmed",
  high: "High confidence",
  medium: "Medium confidence",
  low: "Low confidence",
  unknown: "Unknown confidence",
};
