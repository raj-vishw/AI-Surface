/**
 * The in-memory mock dataset. Built once at module load, deterministically
 * (see random.ts), and internally cross-referenced the same way the real
 * backend's rows are (a Finding really points at a real Asset id here, an
 * Alert really points at a real DetectionMatch id, etc.) — this is
 * "development-only mock data clearly marked as mock" (spec §44/§72), not
 * fabricated production data: every module that serves it is under
 * src/mocks/, imported only by src/api/*.ts's mock branch (see
 * src/api/config.ts), and this file's own existence is documented in the
 * frontend implementation report.
 */
import { mockId, pick, pickWeighted, randInt, randFloat, chance, daysAgo, hoursAgo } from "./random";
import type { Target } from "@/types/target";
import type { Asset, AssetType, AssetStatus } from "@/types/asset";
import type { Finding, FindingCategory, FindingStatus } from "@/types/finding";
import type { Rule, DetectionMatch, Alert, AlertStatus } from "@/types/detection";
import type {
  Investigation,
  InvestigationStatus,
  TimelineEvent,
  InvestigationNote,
  Hypothesis,
  IncidentCluster,
} from "@/types/investigation";
import type {
  Correlation,
  CorrelationNode,
  CorrelationEdge,
  AttackChain,
  AttackChainStage,
  StageType,
  NodeType,
} from "@/types/correlation";
import type { IntelligenceRecord, IndicatorType, RiskScore } from "@/types/intelligence";
import type { Fingerprint, FingerprintCategory } from "@/types/fingerprint";
import type { AISession, AIMessage, AIToolCall, AIResult } from "@/types/ai";
import type { Report, ReportType, EvidencePackage, ControlEvidence } from "@/types/reporting";
import type { Scan, ScanType } from "@/types/scan";
import type { Severity } from "@/lib/severity";

const SEVERITIES: [Severity, number][] = [
  ["critical", 4],
  ["high", 10],
  ["medium", 22],
  ["low", 28],
  ["informational", 14],
];

// --- Targets ------------------------------------------------------------

export const targets: Target[] = [
  {
    id: mockId("target1"),
    name: "Northwind Commerce",
    type: "DOMAIN",
    value: "northwind-example.com",
    description: "Primary e-commerce estate — authorized external assessment.",
    authorizationStatus: "AUTHORIZED",
    createdAt: daysAgo(120),
    updatedAt: daysAgo(2),
  },
  {
    id: mockId("target2"),
    name: "Meridian AI Labs",
    type: "DOMAIN",
    value: "meridian-ai-example.com",
    description: "AI product infrastructure — internal red-team engagement.",
    authorizationStatus: "AUTHORIZED",
    createdAt: daysAgo(64),
    updatedAt: daysAgo(1),
  },
];

const primaryTargetId = targets[0].id;

// --- Assets ---------------------------------------------------------------

const ASSET_TYPE_WEIGHTS: [AssetType, number][] = [
  ["DOMAIN", 1],
  ["SUBDOMAIN", 10],
  ["HOST", 4],
  ["IP", 6],
  ["PORT", 8],
  ["SERVICE", 6],
  ["HTTP_ENDPOINT", 8],
  ["API_ENDPOINT", 5],
  ["AI_ENDPOINT", 2],
  ["MODEL_ENDPOINT", 1],
];

const SUBDOMAIN_LABELS = [
  "www", "api", "app", "admin", "portal", "cdn", "static", "mail",
  "auth", "gateway", "dev", "staging", "checkout", "payments", "cms",
];

function buildAssets(targetId: string, domain: string, count: number): Asset[] {
  const out: Asset[] = [];
  for (let i = 0; i < count; i++) {
    const type = i === 0 ? "DOMAIN" : pickWeighted(ASSET_TYPE_WEIGHTS);
    const status: AssetStatus = pickWeighted([
      ["ACTIVE", 70],
      ["DISCOVERED", 15],
      ["INACTIVE", 10],
      ["RETIRED", 5],
    ]);
    const firstSeen = daysAgo(randInt(5, 110));
    const confidence = randFloat(0.4, 1.0);
    const base: Asset = {
      id: mockId(`asset${i}`),
      targetId,
      type,
      status,
      confidence,
      confidenceLevel: confidence >= 1 ? "CONFIRMED" : confidence >= 0.75 ? "HIGH" : confidence >= 0.5 ? "MEDIUM" : "LOW",
      hostname: null,
      ip: null,
      port: null,
      protocol: null,
      url: null,
      technology: null,
      provider: null,
      model: null,
      environment: chance(0.2) ? "staging" : "production",
      source: pick(["dns_discovery", "http_discovery", "network_discovery", "endpoint_discovery"]),
      identityKey: "",
      firstSeen,
      lastSeen: chance(0.85) ? hoursAgo(randInt(1, 72)) : firstSeen,
      createdAt: firstSeen,
      updatedAt: hoursAgo(randInt(1, 200)),
      metadata: {},
    };

    if (type === "DOMAIN") base.hostname = domain;
    else if (type === "SUBDOMAIN" || type === "HOST") base.hostname = `${pick(SUBDOMAIN_LABELS)}.${domain}`;
    else if (type === "IP") base.ip = `203.0.${randInt(1, 254)}.${randInt(1, 254)}`;
    else if (type === "PORT" || type === "SERVICE") {
      base.ip = `203.0.${randInt(1, 254)}.${randInt(1, 254)}`;
      base.port = pick([22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200]);
      base.protocol = base.port === 22 ? "ssh" : [80, 8080, 443, 8443].includes(base.port) ? "http" : "tcp";
    } else if (type === "HTTP_ENDPOINT" || type === "API_ENDPOINT" || type === "AI_ENDPOINT") {
      const host = `${pick(SUBDOMAIN_LABELS)}.${domain}`;
      base.hostname = host;
      base.url = `https://${host}${pick(["/", "/login", "/v1/status", "/v1/chat/completions", "/admin", "/checkout"])}`;
      if (type === "AI_ENDPOINT") {
        base.provider = pick(["OpenAI-compatible", "self-hosted", "Anthropic-compatible"]);
        base.model = pick(["gpt-4-class", "llama-3-70b", "internal-finetune-v2"]);
      }
    } else if (type === "MODEL_ENDPOINT") {
      base.hostname = `models.${domain}`;
      base.url = `https://models.${domain}/v1/models`;
      base.provider = "self-hosted";
      base.model = pick(["llama-3-70b", "mistral-large", "internal-finetune-v2"]);
    }
    base.identityKey = `${type}:${base.hostname ?? base.ip ?? base.url}:${base.port ?? ""}`;
    out.push(base);
  }
  return out;
}

export const assets: Asset[] = [
  ...buildAssets(targets[0].id, targets[0].value, 46),
  ...buildAssets(targets[1].id, targets[1].value, 24),
];

const assetsByTarget = (targetId: string) => assets.filter((a) => a.targetId === targetId);

// --- Fingerprints / Technologies -------------------------------------------

const TECH_CATALOG: [string, FingerprintCategory, string][] = [
  ["nginx", "web_server", "F5"],
  ["Next.js", "framework", "Vercel"],
  ["React", "frontend", ""],
  ["PostgreSQL", "database", ""],
  ["Redis", "database", ""],
  ["Cloudflare", "cdn", "Cloudflare"],
  ["WordPress", "cms", ""],
  ["Stripe", "api", "Stripe"],
  ["Auth0", "authentication", "Okta"],
  ["Datadog", "monitoring", ""],
  ["Google Analytics", "analytics", "Google"],
  ["AWS ALB", "reverse_proxy", "Amazon"],
  ["OpenAI-compatible API", "ai_provider", ""],
  ["vLLM", "ai_platform", ""],
  ["Kubernetes Ingress", "infrastructure", ""],
];

function buildFingerprints(targetAssets: Asset[]): Fingerprint[] {
  const out: Fingerprint[] = [];
  for (const asset of targetAssets) {
    if (asset.type === "PORT" || asset.type === "SERVICE" || !chance(0.55)) continue;
    const n = randInt(1, 3);
    for (let i = 0; i < n; i++) {
      const [tech, category, vendor] = pick(TECH_CATALOG);
      out.push({
        id: mockId(`fp${out.length}`),
        assetId: asset.id,
        targetId: asset.targetId,
        category,
        technology: tech,
        product: tech,
        vendor,
        version: chance(0.6) ? `${randInt(1, 22)}.${randInt(0, 12)}.${randInt(0, 9)}` : "",
        confidence: randFloat(0.5, 1.0),
        status: pickWeighted([["ACTIVE", 85], ["INACTIVE", 15]] as [Fingerprint["status"], number][]),
        firstSeen: asset.firstSeen,
        lastSeen: asset.lastSeen,
      });
    }
  }
  return out;
}

export const fingerprints: Fingerprint[] = assets.flatMap((a) => buildFingerprints([a]));

// --- Rules / Detection matches / Alerts ------------------------------------

const BUILTIN_RULES: { name: string; description: string; severity: Severity; category: string }[] = [
  { name: "Repeated authentication failures", description: "3+ failed authentication findings against the same asset within 15 minutes.", severity: "high", category: "authentication" },
  { name: "Newly exposed administrative endpoint", description: "A previously unseen /admin-shaped endpoint became reachable.", severity: "high", category: "exposure" },
  { name: "Expiring TLS certificate", description: "A certificate finding is within its configured expiry warning window.", severity: "medium", category: "certificate" },
  { name: "Missing security headers cluster", description: "3+ missing-security-header findings on the same asset.", severity: "low", category: "security_headers" },
  { name: "Exposed AI endpoint without auth", description: "An AI/model endpoint asset with no authentication-related finding coverage.", severity: "critical", category: "exposure" },
];

export const rules: Rule[] = [
  ...BUILTIN_RULES.map((r, i) => ({
    id: mockId(`rule${i}`),
    targetId: primaryTargetId,
    name: r.name,
    description: r.description,
    status: "enabled" as const,
    severity: r.severity,
    confidence: pick(["medium", "high", "very_high"] as const),
    ruleType: pick(["threshold", "sequence", "aggregation", "simple"] as const),
    category: r.category,
    tags: ["builtin"],
    createdBy: "system",
    createdAt: daysAgo(110),
    updatedAt: daysAgo(randInt(1, 40)),
  })),
  {
    id: mockId("rule-custom-1"),
    targetId: primaryTargetId,
    name: "Custom: checkout subdomain drift",
    description: "Analyst-authored rule watching for new assets under checkout.*",
    status: "enabled",
    severity: "medium",
    confidence: "high",
    ruleType: "simple",
    category: "exposure",
    tags: ["custom", "commerce"],
    createdBy: "analyst.rao",
    createdAt: daysAgo(30),
    updatedAt: daysAgo(5),
  },
];

export const detectionMatches: DetectionMatch[] = Array.from({ length: 22 }, (_, i) => {
  const rule = pick(rules);
  return {
    id: mockId(`match${i}`),
    targetId: rule.targetId,
    ruleId: rule.id,
    ruleVersion: randInt(1, 3),
    ruleName: rule.name,
    status: pickWeighted([["open", 40], ["acknowledged", 20], ["resolved", 30], ["suppressed", 10]]),
    fingerprint: mockId(`fp-match${i}`),
    firstObservedAt: daysAgo(randInt(0, 60)),
    lastObservedAt: hoursAgo(randInt(1, 96)),
    createdAt: daysAgo(randInt(0, 60)),
  };
});

export const alerts: Alert[] = detectionMatches
  .filter(() => chance(0.75))
  .map((m, i) => {
    const rule = rules.find((r) => r.id === m.ruleId)!;
    const status: AlertStatus = pickWeighted([
      ["open", 35],
      ["acknowledged", 20],
      ["investigating", 15],
      ["resolved", 25],
      ["suppressed", 5],
    ]);
    return {
      id: mockId(`alert${i}`),
      targetId: m.targetId,
      detectionMatchId: m.id,
      title: `${rule.name} — ${pick(assetsByTarget(m.targetId)).hostname ?? "asset"}`,
      description: rule.description,
      severity: rule.severity,
      confidence: pick(["low", "medium", "high", "very_high"] as const),
      status,
      investigationId: null,
      ruleName: rule.name,
      firstObservedAt: m.firstObservedAt,
      lastObservedAt: m.lastObservedAt,
      createdAt: m.createdAt,
      updatedAt: hoursAgo(randInt(1, 48)),
    };
  });

// --- Findings ---------------------------------------------------------------

const FINDING_TEMPLATES: { title: string; category: FindingCategory; severity: Severity; description: string; remediation: string }[] = [
  { title: "Missing Content-Security-Policy header", category: "security_headers", severity: "low", description: "The response does not set a Content-Security-Policy header, weakening XSS defense-in-depth.", remediation: "Configure a restrictive CSP appropriate to the application's own script/style sources." },
  { title: "Missing Strict-Transport-Security header", category: "security_headers", severity: "medium", description: "HSTS is not set, allowing a downgrade to plain HTTP on first visit.", remediation: "Set Strict-Transport-Security with an appropriate max-age and includeSubDomains." },
  { title: "TLS certificate expiring soon", category: "certificate", severity: "medium", description: "The presented certificate expires within the configured warning window.", remediation: "Renew the certificate before expiry; consider automated renewal." },
  { title: "Exposed administrative interface", category: "exposure", severity: "high", description: "An administrative login interface is reachable without network restriction.", remediation: "Restrict access by network ACL/VPN, or place behind an authenticated proxy." },
  { title: "Outdated web server version", category: "technology", severity: "medium", description: "The identified web server version has known post-release security fixes.", remediation: "Upgrade to a currently maintained release." },
  { title: "API endpoint without rate limiting", category: "api", severity: "medium", description: "No rate-limiting behavior was observed on repeated identical requests.", remediation: "Apply per-client rate limiting, especially on authentication and search endpoints." },
  { title: "Verbose error response", category: "information_disclosure", severity: "low", description: "An error response included a stack trace / internal path detail.", remediation: "Return a generic error to clients; log detail server-side only." },
  { title: "Weak TLS cipher suite offered", category: "cryptography", severity: "medium", description: "The server offers a cipher suite considered weak by current guidance.", remediation: "Disable the weak cipher suite in the TLS server configuration." },
  { title: "AI endpoint accepts requests without authentication", category: "authentication", severity: "critical", description: "A model/AI endpoint responded successfully with no credential presented.", remediation: "Require authentication on every AI/model endpoint; verify no anonymous path remains." },
  { title: "Open redirect on login flow", category: "web", severity: "medium", description: "The login flow's redirect parameter accepts an arbitrary external host.", remediation: "Validate the redirect target against an allowlist of same-origin paths." },
  { title: "Subdomain takeover candidate", category: "infrastructure", severity: "high", description: "A CNAME points at a provider resource that is not currently claimed.", remediation: "Remove the dangling DNS record or re-claim the target resource." },
  { title: "Cloud storage bucket publicly listable", category: "exposure", severity: "high", description: "A discovered cloud storage resource allows anonymous listing.", remediation: "Restrict bucket ACLs to authorized principals only." },
];

export function buildFindings(): Finding[] {
  const out: Finding[] = [];
  for (let i = 0; i < 30; i++) {
    const asset = pick(assets);
    const tmpl = pick(FINDING_TEMPLATES);
    const status: FindingStatus = pickWeighted([
      ["open", 55],
      ["resolved", 25],
      ["accepted_risk", 10],
      ["false_positive", 5],
      ["reopened", 5],
    ]);
    const firstSeen = daysAgo(randInt(0, 90));
    out.push({
      id: mockId(`finding${i}`),
      targetId: asset.targetId,
      assetId: asset.id,
      endpointId: null,
      scanId: mockId(`scan-ref${i}`),
      detectorId: `${tmpl.category}.${tmpl.title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
      detectorVersion: 1,
      title: tmpl.title,
      description: tmpl.description,
      category: tmpl.category,
      scope: "asset",
      severity: tmpl.severity,
      detectorSeverity: tmpl.severity,
      confidence: randFloat(0.55, 1),
      status,
      remediation: tmpl.remediation,
      references: [{ label: "OWASP", url: "https://owasp.org/" }],
      severityOverridden: false,
      severityOverrideReason: "",
      severityOverriddenAt: null,
      suppressionReason: status === "false_positive" ? "Confirmed benign after manual review." : "",
      firstSeen,
      lastSeen: chance(0.8) ? hoursAgo(randInt(1, 72)) : firstSeen,
      resolvedAt: status === "resolved" ? hoursAgo(randInt(1, 200)) : null,
      createdAt: firstSeen,
      updatedAt: hoursAgo(randInt(1, 300)),
      assetName: asset.hostname ?? asset.ip ?? asset.url ?? undefined,
    });
  }
  return out;
}

export const findings: Finding[] = buildFindings();

// --- Investigations / timeline / notes / hypotheses / clusters ------------

const INVESTIGATION_TITLES = [
  "Suspicious authentication pattern on checkout subdomain",
  "Cluster of newly exposed administrative surfaces",
  "AI endpoint anomalous usage investigation",
  "Certificate & TLS posture review — Q1",
  "Subdomain takeover candidate follow-up",
  "Repeated high-severity findings on payments service",
  "Cross-asset technology drift after vendor migration",
  "Correlated alert spike — network scan window",
  "Data exposure review — cloud storage findings",
];

export const investigations: Investigation[] = INVESTIGATION_TITLES.map((title, i) => {
  const status: InvestigationStatus = pickWeighted([
    ["new", 10],
    ["open", 25],
    ["investigating", 25],
    ["contained", 10],
    ["resolved", 20],
    ["closed", 10],
  ]);
  const createdAt = daysAgo(randInt(1, 80));
  const isClosed = status === "closed" || status === "resolved";
  return {
    id: mockId(`inv${i}`),
    targetId: primaryTargetId,
    title,
    description: `Investigation opened from correlated activity: ${title.toLowerCase()}.`,
    status,
    priority: pickWeighted([["low", 15], ["normal", 40], ["high", 30], ["urgent", 15]]),
    severity: pickWeighted(SEVERITIES),
    confidence: pickWeighted([["very_low", 5], ["low", 15], ["medium", 40], ["high", 30], ["very_high", 10]]),
    createdBy: pick(["analyst.rao", "analyst.chen", "system"]),
    assignedTo: pick(["analyst.rao", "analyst.chen", "unassigned"]),
    detectedAt: createdAt,
    firstObservedAt: createdAt,
    lastObservedAt: hoursAgo(randInt(1, 120)),
    version: randInt(1, 6),
    createdAt,
    updatedAt: hoursAgo(randInt(1, 120)),
    closedAt: isClosed ? hoursAgo(randInt(1, 500)) : null,
  };
});

export const timelineEvents: TimelineEvent[] = investigations.flatMap((inv) =>
  Array.from({ length: randInt(3, 7) }, (_, i) => ({
    id: mockId(`tl${inv.id}${i}`),
    targetId: inv.targetId,
    investigationId: inv.id,
    timestamp: daysAgo(randInt(0, 60)),
    type: pick(["finding_added", "evidence_attached", "note_added", "status_changed", "ai_analysis", "asset_change"] as const),
    sourceType: pick(["finding", "asset", "alert", "correlation"]),
    sourceId: pick(findings).id,
    title: pick([
      "Finding attached as evidence",
      "Investigation status updated",
      "Analyst note added",
      "AI investigation summary generated",
      "Related asset change observed",
    ]),
    description: "See linked evidence for full detail.",
    severity: pickWeighted(SEVERITIES),
    actor: pick(["analyst.rao", "analyst.chen", "system"]),
    createdAt: daysAgo(randInt(0, 60)),
  })).sort((a, b) => a.timestamp.localeCompare(b.timestamp)),
);

export const notes: InvestigationNote[] = investigations
  .filter(() => chance(0.6))
  .map((inv, i) => ({
    id: mockId(`note${i}`),
    investigationId: inv.id,
    authorId: pick(["analyst.rao", "analyst.chen"]),
    content: pick([
      "Confirmed the affected asset is internet-facing; escalating priority.",
      "Cross-referenced with last week's scan — pattern is new.",
      "Waiting on asset owner confirmation before closing.",
      "AI-suggested next step looks correct; validating manually.",
    ]),
    aiGenerated: false,
    approvedBy: null,
    approvedAt: null,
    createdAt: daysAgo(randInt(0, 40)),
  }));

export const hypotheses: Hypothesis[] = investigations
  .filter(() => chance(0.4))
  .map((inv, i) => ({
    id: mockId(`hyp${i}`),
    investigationId: inv.id,
    title: "Credential stuffing against checkout login",
    description: "Repeated auth failures followed by a success suggest credential stuffing rather than a single user error.",
    status: pick(["proposed", "supported", "refuted", "confirmed"] as const),
    confidence: pick(["low", "medium", "high"] as const),
    createdBy: pick(["analyst.rao", "analyst.chen"]),
    createdAt: daysAgo(randInt(0, 30)),
    updatedAt: daysAgo(randInt(0, 10)),
  }));

export const incidentClusters: IncidentCluster[] = Array.from({ length: 6 }, (_, i) => {
  const status = pickWeighted([["suggested", 45], ["accepted", 35], ["rejected", 20]] as [IncidentCluster["status"], number][]);
  return {
    id: mockId(`cluster${i}`),
    targetId: primaryTargetId,
    title: pick([
      "Auth-failure spike + new admin endpoint (2h window)",
      "TLS + security-header cluster on payments service",
      "Multiple AI endpoints exposed after deploy",
      "Subdomain drift following DNS change",
    ]),
    confidence: pick(["medium", "high", "very_high"] as const),
    status,
    acceptedInvestigationId: status === "accepted" ? pick(investigations).id : null,
    memberCount: randInt(2, 6),
    createdAt: daysAgo(randInt(0, 30)),
    updatedAt: daysAgo(randInt(0, 10)),
  };
});

// --- Correlations / nodes / edges / attack chains --------------------------

export const correlations: Correlation[] = Array.from({ length: 8 }, (_, i) => ({
  id: mockId(`corr${i}`),
  targetId: primaryTargetId,
  title: pick([
    "Temporal cluster: auth failures + new endpoint",
    "Shared technology across 4 findings",
    "Escalation pattern on payments asset",
    "Indicator overlap with threat-feed record",
  ]),
  description: "Correlated from temporal proximity and shared-asset signals.",
  status: pickWeighted([["candidate", 35], ["confirmed", 45], ["dismissed", 15], ["merged", 5]] as [Correlation["status"], number][]),
  severity: pickWeighted(SEVERITIES),
  confidence: pick(["low", "medium", "high"] as const),
  score: randInt(20, 95),
  strategy: pick(["temporal_proximity", "shared_asset", "technology_overlap", "intelligence_context"]),
  createdAt: daysAgo(randInt(0, 45)),
  updatedAt: hoursAgo(randInt(1, 96)),
}));

const NODE_TYPES: NodeType[] = ["finding", "detection_match", "alert", "asset", "endpoint", "intelligence_record", "investigation"];

export const correlationNodes: CorrelationNode[] = correlations.flatMap((c) =>
  Array.from({ length: randInt(3, 6) }, (_, i) => {
    const type = pick(NODE_TYPES);
    const findingRef = type === "finding" ? pick(findings) : null;
    const assetRef = type === "asset" ? pick(assets) : null;
    const referenceId = findingRef?.id ?? assetRef?.id ?? mockId(`ref${i}`);
    const label = findingRef?.title ?? assetRef?.hostname ?? assetRef?.ip ?? assetRef?.url ?? `${type} evidence`;
    return {
      id: mockId(`node${c.id}${i}`),
      correlationId: c.id,
      type,
      referenceId,
      role: i === 0 ? "trigger" : "supporting",
      label,
    } as CorrelationNode;
  }),
);

export const correlationEdges: CorrelationEdge[] = correlations.flatMap((c) => {
  const nodes = correlationNodes.filter((n) => n.correlationId === c.id);
  const edges: CorrelationEdge[] = [];
  for (let i = 1; i < nodes.length; i++) {
    edges.push({
      id: mockId(`edge${c.id}${i}`),
      correlationId: c.id,
      sourceNodeId: nodes[0].id,
      targetNodeId: nodes[i].id,
      relationship: pick(["temporal_proximity", "same_asset", "shared_technology", "shared_indicator", "escalation"] as const),
      confidence: pick(["low", "medium", "high"] as const),
    });
  }
  return edges;
});

const STAGE_SEQUENCE: StageType[] = [
  "initial_activity",
  "authentication",
  "discovery_signal",
  "privilege_change",
  "execution",
  "persistence_signal",
  "network_activity",
  "data_access",
  "impact_signal",
];

export const attackChains: AttackChain[] = correlations
  .filter((c) => c.status === "confirmed")
  .slice(0, 4)
  .map((c, i) => ({
    id: mockId(`chain${i}`),
    correlationId: c.id,
    name: `Attack chain — ${c.title}`,
    description: "A narrative reconstruction from correlated evidence — not proof of a confirmed attack.",
    confidence: c.confidence,
    severity: c.severity,
    status: pick(["candidate", "confirmed"] as const),
    createdAt: c.createdAt,
    updatedAt: c.updatedAt,
  }));

export const attackChainStages: AttackChainStage[] = attackChains.flatMap((chain) => {
  const n = randInt(3, 6);
  const stages = STAGE_SEQUENCE.slice(0, n);
  return stages.map((stage, order) => ({
    id: mockId(`stage${chain.id}${order}`),
    attackChainId: chain.id,
    stage,
    order,
    confidence: pick(["low", "medium", "high"] as const),
    evidence: [{ type: pick(NODE_TYPES), id: pick(findings).id }],
  }));
});

// --- Intelligence -----------------------------------------------------------

const INDICATOR_TYPES: IndicatorType[] = ["domain", "subdomain", "ipv4", "url", "hash", "certificate", "technology"];

export const intelligenceRecords: IntelligenceRecord[] = Array.from({ length: 26 }, (_, i) => {
  const type = pick(INDICATOR_TYPES);
  return {
    id: mockId(`intel${i}`),
    targetId: primaryTargetId,
    indicatorType: type,
    indicatorValue:
      type === "ipv4" ? `198.51.${randInt(1, 254)}.${randInt(1, 254)}` :
      type === "hash" ? `${randInt(1e8, 9e8).toString(16)}${randInt(1e8, 9e8).toString(16)}` :
      type === "url" ? `https://${pick(SUBDOMAIN_LABELS)}.northwind-example.com/` :
      `${pick(SUBDOMAIN_LABELS)}.northwind-example.com`,
    providerId: pick(["local", "dns_provider", "certificate_provider", "reputation_provider", "threat_feed"]),
    providerVersion: "1.0.0",
    sourceType: pick(["local", "dns", "certificate", "reputation", "threat_feed"] as const),
    confidence: pick(["low", "medium", "high"] as const),
    malicious: chance(0.12),
    suspicious: chance(0.22),
    summary: pick([
      "Observed in threat-feed watchlist within the last 30 days.",
      "Certificate issued by a low-reputation CA.",
      "No adverse reputation signal found.",
      "Shares infrastructure with a known scanning range.",
    ]),
    observedAt: daysAgo(randInt(0, 60)),
    expiresAt: chance(0.3) ? daysAgo(-randInt(1, 30)) : null,
    createdAt: daysAgo(randInt(0, 60)),
  };
});

export const riskScores: RiskScore[] = [
  ...assets.filter(() => chance(0.5)).map((a, i) => ({
    id: mockId(`risk-a${i}`),
    targetId: a.targetId,
    entityType: "asset" as const,
    entityId: a.id,
    score: randInt(5, 95),
    severity: pickWeighted(SEVERITIES),
    confidence: pick(["low", "medium", "high"]),
    modelVersion: "v1",
    factors: [
      { name: "Finding severity", points: randInt(10, 40), description: "Open critical/high findings on this asset." },
      { name: "Exposure", points: randInt(5, 25), description: "Internet-facing with an open administrative surface." },
    ],
    explanation: "Derived from open finding severity and exposure signals.",
    calculatedAt: hoursAgo(randInt(1, 72)),
  })),
  ...investigations.filter(() => chance(0.4)).map((inv, i) => ({
    id: mockId(`risk-i${i}`),
    targetId: inv.targetId,
    entityType: "investigation" as const,
    entityId: inv.id,
    score: randInt(10, 90),
    severity: pickWeighted(SEVERITIES),
    confidence: pick(["low", "medium", "high"]),
    modelVersion: "v1",
    factors: [{ name: "Severity", points: randInt(20, 50), description: "Investigation severity and confidence." }],
    explanation: "Derived from investigation severity and confidence.",
    calculatedAt: hoursAgo(randInt(1, 72)),
  })),
];

// --- AI sessions / messages / tool calls / results -------------------------

export const aiSessions: AISession[] = investigations.slice(0, 4).map((inv, i) => ({
  id: mockId(`aisession${i}`),
  targetId: inv.targetId,
  investigationId: inv.id,
  userId: "analyst.rao",
  createdAt: daysAgo(randInt(0, 20)),
  updatedAt: hoursAgo(randInt(1, 48)),
}));

export const aiMessages: AIMessage[] = aiSessions.flatMap((s) => [
  { id: mockId(`m${s.id}1`), sessionId: s.id, role: "user" as const, content: "Summarize what we know about this investigation so far.", createdAt: s.createdAt },
  { id: mockId(`m${s.id}2`), sessionId: s.id, role: "assistant" as const, content: "See structured summary.", createdAt: s.createdAt },
]);

export const aiToolCalls: AIToolCall[] = aiSessions.flatMap((s, i) => [
  { id: mockId(`tool${s.id}1`), sessionId: s.id, requestId: null, targetId: s.targetId, tool: "finding_search", arguments: { investigation_id: s.investigationId }, resultStatus: "success" as const, resultSummary: `Returned ${randInt(2, 6)} findings`, createdAt: s.createdAt },
  { id: mockId(`tool${s.id}2`), sessionId: s.id, requestId: null, targetId: s.targetId, tool: "timeline_query", arguments: { investigation_id: s.investigationId }, resultStatus: "success" as const, resultSummary: `Returned ${randInt(3, 8)} timeline events`, createdAt: s.createdAt },
  ...(i === 0 ? [{ id: mockId(`tool${s.id}3`), sessionId: s.id, requestId: null, targetId: s.targetId, tool: "asset_lookup", arguments: {}, resultStatus: "empty" as const, resultSummary: "No matching asset found", createdAt: s.createdAt }] : []),
]);

export const aiResults: AIResult[] = aiSessions.map((s, i) => {
  const relatedFindings = findings.filter((f) => f.targetId === s.targetId).slice(0, 3);
  const citations = relatedFindings.map((f) => `[finding:${f.id}]`);
  return {
    id: mockId(`airesult${i}`),
    sessionId: s.id,
    taskType: "investigation_summary" as const,
    content: "Structured summary available below.",
    structured: {
      summary: "This investigation centers on repeated authentication activity against a single checkout-facing asset, corroborated by two related findings.",
      observed: [
        `Repeated authentication-failure finding recorded against the affected asset ${citations[0] ?? ""}`.trim(),
        `A related exposure finding was recorded on the same asset ${citations[1] ?? ""}`.trim(),
      ],
      inferred: [
        `The temporal proximity of these findings suggests a single coordinated attempt rather than unrelated noise ${citations[2] ?? ""}`.trim(),
      ],
      unknown: ["Whether the attempted credentials were valid for any real account."],
      evidenceGaps: ["No WAF/edge log evidence is available for this window."],
      nextSteps: ["Confirm with the asset owner whether any account lockouts occurred in this window."],
      questions: ["Should this asset's login endpoint have stricter rate limiting applied?"],
      citations,
    },
    provider: "mock",
    model: "default",
    confidence: pick(["low", "medium", "high"] as const),
    citations,
    fabricatedCitationsRemoved: [],
    unsupportedClaimsRewritten: 0,
    attributionRejected: false,
    truncated: false,
    inputTokens: randInt(400, 1200),
    outputTokens: randInt(150, 400),
    latencyMs: randInt(300, 2200),
    createdAt: s.updatedAt,
  };
});

// --- Reports / evidence / control evidence ---------------------------------

const REPORT_TYPES: ReportType[] = ["investigation", "asset", "correlation", "attack_surface", "detection", "executive", "audit"];

export const reports: Report[] = Array.from({ length: 11 }, (_, i) => {
  const type = REPORT_TYPES[i % REPORT_TYPES.length];
  const subjectId =
    type === "investigation" ? pick(investigations).id :
    type === "asset" ? pick(assets).id :
    type === "correlation" ? pick(correlations).id :
    null;
  return {
    id: mockId(`report${i}`),
    targetId: primaryTargetId,
    reportType: type,
    subjectId,
    version: randInt(1, 3),
    title: `${type[0].toUpperCase()}${type.slice(1).replace("_", " ")} report`,
    status: pickWeighted([["generated", 45], ["reviewed", 30], ["approved", 25]] as [Report["status"], number][]),
    contentHash: `sha256:${randInt(1e8, 9e8).toString(16)}${randInt(1e8, 9e8).toString(16)}`,
    generatedBy: pick(["analyst.rao", "analyst.chen"]),
    approvedBy: chance(0.4) ? "lead.singh" : null,
    approvedAt: chance(0.4) ? hoursAgo(randInt(1, 100)) : null,
    approvalNotes: chance(0.4) ? "Reviewed against evidence; approved for distribution." : "",
    createdAt: daysAgo(randInt(0, 40)),
    generatedAt: daysAgo(randInt(0, 40)),
  };
});

export const evidencePackages: EvidencePackage[] = reports
  .filter(() => chance(0.4))
  .map((r, i) => ({
    id: mockId(`pkg${i}`),
    targetId: r.targetId,
    reportId: r.id,
    itemCount: randInt(2, 9),
    manifestHash: `sha256:${randInt(1e8, 9e8).toString(16)}${randInt(1e8, 9e8).toString(16)}`,
    createdBy: r.generatedBy,
    createdAt: r.createdAt,
  }));

export const controlEvidence: ControlEvidence[] = Array.from({ length: 9 }, (_, i) => ({
  id: mockId(`ctrl${i}`),
  targetId: primaryTargetId,
  controlId: pick(["AC-2", "SC-8", "SI-4", "encryption-at-rest", "access-review"]),
  evidenceType: pick(["finding", "alert", "asset", "investigation"] as const),
  referenceId: pick(findings).id,
  description: "Linked evidence supporting this control's activity.",
  collectedAt: daysAgo(randInt(0, 60)),
}));

// --- Scans ------------------------------------------------------------------

const SCAN_TYPES: ScanType[] = ["http", "network", "dns", "subdomain", "endpoint", "fingerprint"];

export const scans: Scan[] = Array.from({ length: 16 }, (_, i) => {
  const status = pickWeighted([["completed", 75], ["failed", 10], ["running", 8], ["queued", 5], ["cancelled", 2]] as [Scan["status"], number][]);
  const startedAt = daysAgo(randInt(0, 30));
  const durationMs = status === "completed" || status === "failed" ? randInt(2_000, 240_000) : null;
  return {
    id: mockId(`scan${i}`),
    targetId: primaryTargetId,
    targetValue: targets[0].value,
    scanType: pick(SCAN_TYPES),
    status,
    startedAt,
    completedAt: durationMs ? new Date(new Date(startedAt).getTime() + durationMs).toISOString() : null,
    durationMs,
    assetsDiscovered: status === "completed" ? randInt(0, 12) : 0,
    findingsDiscovered: status === "completed" ? randInt(0, 8) : 0,
    error: status === "failed" ? "connection timed out after 3 retries" : null,
  };
});
