# Changelog

All notable changes to this project are documented here, grouped by
development phase (see `../doc_by_me/`). This project has no public
releases yet — versions below refer to development phases, not semver
tags.

## Phase 15 — Production Hardening, Deployment & Final Security Audit

The final planned development phase. No new product functionality was
added — this phase audited the entire Phases 1–14 codebase and fixed
what the audit found, per its own explicit scope ("only fix issues
discovered during Phase 15 that are necessary for production
readiness").

### Fixed

- **`.gitignore` excluded `docs/`, `CHANGELOG.md`, and (via its `.env.*`
  pattern) `.env.example` from version control entirely** — every
  documentation deliverable from Phases 1–14 existed only on the local
  filesystem, never in git, despite being reported complete in every
  phase's own report. Removed the erroneous `docs/`/`CHANGELOG.md` lines
  and added a `!.env.example` negation (matching the pattern
  `.dockerignore` already used correctly).
- **SSRF: outbound HTTP requests validated scope by hostname only, never
  the resolved IP** — a target whose DNS resolved (or whose redirect
  chain led) to a cloud-metadata address (`169.254.169.254`) would
  previously have been queried. Added `internal/httpclient/ssrf.go`: a
  `net.Dialer.Control` hook refusing `169.254.0.0/16` and
  `fd00:ec2::254` at the resolved-IP level, immune to DNS rebinding.
  Loopback and RFC1918/private addresses remain unaffected (authorized
  internal-network testing is a supported use case).
- **6 Go standard-library vulnerabilities** (GO-2026-6218, -6090, -6089,
  -6088, -5972, -5026) in the pinned `go 1.26.5` toolchain — bumped
  `go.mod`'s `go` directive to `1.26.6`; `govulncheck ./...` confirms
  zero vulnerabilities after the bump.
- **No production/staging configuration separation** — added
  `configs/production/config.yaml` and three new startup guard rails in
  `internal/config.Config.Validate()` rejecting `logging.level: debug`,
  `security.require_authorization: false`, or `database.ssl_mode:
  disable` whenever `AI_SURFACE_APP_ENV=production`.
- **No race-detector testing in CI/Makefile** — added `make test-race`
  and a corresponding CI step; full suite re-verified clean.
- **No dependency/secret/container vulnerability scanning in CI** — added
  a `security` CI job (`govulncheck`, `gitleaks` via `.gitleaks.toml`,
  Trivy image scan) and `make vuln-check`/`secret-scan`/`security-check`.
- **No defensive HTTP response headers** — added
  `securityHeadersMiddleware` (CSP, `X-Content-Type-Options`,
  `Referrer-Policy`, `Permissions-Policy`, `X-Frame-Options`) to every
  `internal/httpserver` response.
- **Stale README status line** — still read "Phase 4" after 11 more
  phases shipped; rewritten to reflect Phase 15.

### Added

- `GET /live` — an explicit liveness endpoint alias for `GET /health`
  (`internal/httpserver`).
- `internal/service/reporting/isolation_test.go` — the first direct test
  proving `buildInvestigationReport` rejects a cross-target subject
  (this platform's core "project isolation" boundary, since no
  authentication/RBAC layer exists).
- `docs/operations/{production-readiness,deployment,disaster-recovery,
  runbook,troubleshooting,release-checklist,production-readiness-report}.md`,
  `docs/security/{production-hardening,threat-model,
  final-security-checklist,final-audit}.md`,
  `docs/architecture/overview.md`, `CONTRIBUTING.md`.
- `.gitleaks.toml` — CI secret-scanning config with a narrow, documented
  allowlist for this platform's own redaction-engine test fixtures.

### Design Notes

- No authentication/RBAC layer was added — out of scope for this phase
  (phase15.md explicitly forbids new product features) and a deliberate
  architectural characteristic of this single-operator CLI tool, not an
  oversight; documented as an explicitly accepted risk in
  `docs/security/final-audit.md` (SEC-01) and
  `docs/security/threat-model.md` (T1).
- Container image vulnerability scanning was added to CI but could not
  be executed in this development sandbox (no Docker daemon access) —
  documented honestly rather than claimed verified.
- Backup/restore was documented with a concrete, runnable procedure but
  never executed against a live database in this sandbox (no
  PostgreSQL instance was reachable) — flagged as an open item for the
  first real deployment, not silently skipped.
- See `docs/operations/production-readiness-report.md` for the full
  verdict: **Staging Ready**; **Production Ready for its designed
  single-operator use case**; **not** ready for deployment behind a
  public or multi-user network boundary without first adding
  authentication.

## Phase 14 — Advanced Dashboards, Reporting & Security Analytics

### Added

- `internal/repository/analytics` — read-only aggregate-query
  `Repository` (COUNT/GROUP BY/date_trunc over assets, findings, alerts,
  detection_matches, rules, correlations, correlation_edges,
  attack_chains, attack_chain_stages, investigations,
  intelligence_records, risk_scores, ai_requests, ai_responses,
  ai_tool_calls — no new source-of-truth tables) + `PostgresRepository`.
- `internal/analytics` — the dashboard-facing service layer:
  `ResolveRange`/`DefaultIntervalFor` (24h→hour, 7d/30d→day, 90d→week,
  explicit override, `MaxQueryWindow` rejection), `Cache` (bounded-TTL,
  target-scoped keys — phase14.md §59's cache-isolation requirement),
  `Overview`/`Risk`/`Alerts`/`Detections`/`Findings`/`Assets`/
  `AttackSurface`/`Correlations`/`AttackChains`/`Investigations`/
  `Intelligence`/`AI`/`Posture`/`TimeSeries` (an allowlisted metric
  dispatcher, never an arbitrary SQL fragment).
- `internal/domain/reporting` — `Report` (versioned exactly like Phase
  11's `rule.Version` — immutable once created except `Approve`, which
  only ever touches approval columns), `Package`/`Item` (evidence
  export manifest, SHA-256-hashed, never an authentication mechanism),
  `ControlEvidence` (generic, framework-agnostic — no compliance
  framework hard-coded, since none already exists in this project).
- `internal/repository/reporting` — persistence for all three, including
  `LatestVersion` (the next-version computation every regeneration uses).
- `internal/reporting` — the report-building engine: `Sections`/
  `Render`/`AllCitations`, `ValidateSections` (reuses Phase 13's
  `ai.ValidateCitations` directly — a fabricated evidence reference is
  always stripped, never allowed into a final report), `RedactSections`
  (reuses Phase 13's `ai.Redact` directly), `EncodeCSV`/`EscapeCSVValue`
  (stdlib `encoding/csv` plus OWASP-recommended spreadsheet-formula-
  injection escaping), `EncodeJSON` (relies on `encoding/json`'s
  default HTML-escaping for injection-safe JSON export), `ContentHash`/
  `ItemHash` (SHA-256 integrity hashes).
- `internal/service/reporting` — the bridge: per-report-type section
  builders (investigation/asset/correlation/detection/attack-surface/
  executive/audit — audit reuses the investigation timeline as this
  platform's existing audit trail, no new audit table), `Generate`
  (validates + redacts + hashes + versions + persists),
  `Approve`/`MarkReviewed` (explicit-actor, no double-approval),
  `Export` (JSON/CSV, redacted a second time as defense in depth),
  `CreateEvidencePackage`/`GetManifest`, `RecordControlEvidence`/
  `ControlDashboard` (a control with no evidence never appears — a gap
  represented by absence, never a fabricated zero-evidence row).
- `migrations/000014_create_reporting.sql` — `reports` (version-unique
  per target/type/subject, `NULLS NOT DISTINCT` for target-wide types),
  `evidence_packages`, `evidence_items`, `control_evidence`,
  `dashboard_preferences` (minimal filter-persistence table).
- `cmd/cli/commands/{analytics,reports,evidence_packages,controls}.go`
  — `ai-surface analytics {overview,risk,alerts,detections,findings,
  assets,attack-surface,correlations,attack-chains,investigations,
  intelligence,ai,posture,timeseries}`, `ai-surface report {create,list,
  show,approve,review,export}`, `ai-surface evidence-package {create,show,
  manifest}`, `ai-surface control {record,list,evidence}`.
- `docs/analytics/{metrics,dashboards}.md`, `docs/reporting/reports.md`,
  `docs/compliance/evidence.md`.

### Design notes

- No frontend exists in this codebase (confirmed by inspection) — every
  "dashboard" is `ai-surface analytics`'s tabwriter output; a "preset" is
  simply which handful of subcommands an analyst runs together (see
  `docs/analytics/dashboards.md`'s mapping table).
- No REST API exists beyond `/health`/`/ready` — phase14.md's API
  sections are adapted to CLI subcommands, the same adaptation every
  prior phase applied to its own missing infrastructure.
- No job/worker queue exists yet — report generation runs synchronously,
  the same Phase 13 precedent.
- No metrics library (Prometheus or otherwise) exists — adapted to
  structured `slog` logging at failure points, per Phase 11/12/13.
- Security posture is derived entirely from Phase 10's own risk scores
  (`100 - average latest score`) — never an independently invented
  metric; fully documented (calculation/inputs/weighting/limitations) in
  `docs/analytics/metrics.md`.
- No compliance framework or certification claim is made anywhere —
  `control_evidence` is a generic, analyst-populated ledger only.
- CSV injection is mitigated with the OWASP-recommended leading-quote
  escape; XSS/HTML injection is a non-issue by construction (this
  platform renders no HTML anywhere, and JSON export inherits
  `encoding/json`'s default `<`/`>`/`&` escaping) — verified by test
  rather than assumed.
- Secret redaction reuses Phase 13's `internal/ai.Redact` directly, at
  both report-generation and export time (defense in depth), rather than
  a second redaction implementation.

## Phase 13 — AI-Assisted Investigation & Analyst Copilot

### Added

- `internal/domain/ai` — the AI-assistant persistence model: `Session`
  (target/investigation-scoped conversation), `Message` (immutable once
  created, same discipline as `investigation.Note`), `Request`/`Response`
  (the full AI audit trail — `PromptVersion`, `ContextHash`,
  `ResponseHash`, token counts, latency, citations), `ToolCall`
  (read-only-tool invocation audit). `TaskType` covers 11 tasks
  (investigation summary, alert/detection explanation, correlation/attack-
  chain analysis, timeline summary, intelligence summary, evidence-gap
  analysis, investigation questions, report draft, chat reply).
- `internal/ai` — the self-contained assistant engine (zero DB
  dependency, mirrors `internal/correlation`'s independence from its own
  domain package): `Provider`/`ProviderRegistry` (pluggable, never
  hard-coded to one vendor), `Fact`/`Context`/`Limits`/`Truncate`
  (bounded, deterministic, newest-first context assembly with an explicit
  truncation note), `Redact`/`RedactFact` (secret redaction before
  anything enters a prompt), `ExtractCitations`/`ValidateCitations`
  (fabricated references are always removed, never rewritten),
  `ContainsInjectionAttempt`/`RewriteUnsupportedClaims`/
  `ContainsAttribution` (prompt-injection visibility, hedged-language
  rewriting, hard attribution rejection), `BuildPrompt` (fixed system
  preamble + explicit `<data>`-wrapped untrusted-content framing),
  `StructuredResult` (deterministic `Observed`/`Inferred`/`Unknown`/
  `EvidenceGaps`/`NextSteps`/`Questions`/`Citations`, built by pure
  functions in `investigator.go`/`summarizer.go` — never by parsing a
  provider's free text), `Assistant.Run` (orchestrates build → prompt →
  provider call → validate → derive confidence), `Confidence`
  (`low`/`medium`/`high` — confidence in the interpretation, never a
  probability of attack), `Tool`/`ToolRegistry`/`Executor`/`DataSource`
  (allowlisted, scoped, timeout-bounded, always-audited read-only tools),
  `WithRetries` (bounded, deterministic provider retries).
- `internal/ai/providers/mock` — the default, zero-dependency provider:
  narrates the same deterministic, already-citation-safe context it was
  given; what the entire test suite runs against.
- `internal/ai/providers/openai` — a generic OpenAI-compatible Chat
  Completions client (works against OpenAI, Azure-compatible proxies, or
  self-hosted vLLM/Ollama/llama.cpp); the API key is read from an
  environment variable named in configuration, never stored or logged.
- `internal/ai/tools` — 9 read-only tools (`get_investigation`,
  `get_alert`, `get_detection`, `get_correlation`, `get_timeline`,
  `get_findings`, `get_assets`, `get_intelligence`, `get_risk`), each a
  thin wrapper over `ai.DataSource` — none has any way to write, block,
  scan, or execute anything.
- `internal/repository/ai` — Postgres persistence for
  sessions/messages/requests/responses/tool-calls.
- `internal/service/ai` — the bridge: `Build*Context` (Investigation/
  Alert/Detection/Correlation/Target) assembling `ai.Fact` values from
  Phase 2/7/8/9/10/11/12's own repositories via `facts.go`'s conversion
  functions (every one redacted), `dataSource` (the tool-facing
  `ai.DataSource` implementation, enforcing `TargetID` scoping),
  `Service.runTask` (rate limiting, timeout enforcement, provider
  resolution, full audit persistence — the single choke point every task
  goes through), 9 task methods plus `ChatReply`/`Chat` (session-scoped
  conversation), `SaveNoteFromResponse`/`ApproveNote` (AI-generated notes,
  always unapproved until an explicit, distinct analyst action),
  `CheckHealth`, a process-local sliding-window `rateLimiter`.
- `migrations/000013_create_ai.sql` — `ai_sessions`, `ai_messages`,
  `ai_requests`, `ai_responses`, `ai_tool_calls` (the complete AI audit
  trail — no separate generic audit table); `investigation_notes` gains
  `ai_generated`/`approved_by`/`approved_at` (an AI-drafted note IS an
  `investigation.Note`, not a duplicate model).
- `cmd/cli/commands/ai.go` — `ai-surface ai {status, summarize, analyze,
  questions, report, explain-alert, explain-detection,
  analyze-correlation, session {new,list,show,clear,delete}, chat,
  note approve}`.
- `docs/architecture/ai-assistant.md`, `docs/ai/safety.md`,
  `docs/ai/investigation-guide.md`.

### Design notes

- No REST API exists in this codebase (only `/health`/`/ready`) —
  phase13.md's API sections are adapted to CLI subcommands, the same
  adaptation every prior phase applied to its own missing infrastructure.
- No job/worker queue exists yet — AI requests, including report drafts,
  run synchronously, bounded by a request timeout and cancelable via
  context (see `internal/domain/ai`'s package doc comment).
- No RBAC exists anywhere in this platform — `TargetID` scoping is this
  phase's authorization boundary too, enforced by `internal/service/ai`'s
  `dataSource` and `resolveOrCheckTarget`.
- Determinism: identical `Context` + the mock provider always produce
  identical structured output, because the actual analysis is built by
  pure Go functions over `Context`, never by parsing a provider's own
  free-form text — a real provider's narration is validated against, and
  can always fall back to, that same grounded rendering.
- Rate limiting is process-local (no shared cache/queue infrastructure is
  in active use in this platform yet), a documented Known Limitation
  rather than fabricated cluster-wide infrastructure.

## Phase 12 — Advanced Detection Correlation & Attack-Chain Analysis

### Added

- `internal/domain/correlation` — `Correlation` (system-suggested or
  analyst-confirmed grouping; `open → investigating → confirmed | resolved
  | dismissed`; fingerprint-deduplicated; merge/split lineage via
  `MergedIntoID`/`MergedFromIDs`/`SplitFromID`), `Node` (doubles as this
  platform's CorrelationEvidence record — a reference, never a copy —
  plus `EvidenceRole`), `Edge` (`Relationship`/`Provenance`
  observed-vs-inferred/`EdgeConfidence`, always carries an `Evidence`
  explanation and a `StrategyID`/`StrategyVersion`), `AttackChain` +
  `AttackChainStage` (9 generic stages, gap-aware — a stage with no
  evidence is simply absent, never invented).
- `internal/correlation` — the self-contained, zero-DB correlation
  engine: `Observation`/`Input` (normalized projections of Phase
  2/7/8/10/11 rows), `Strategy` interface + `StrategyRegistry`
  (register/list/enable/disable), `Engine.Correlate` (per-strategy
  failure isolation, deterministic, candidate-count truncation),
  `BuildGraph`/`ConnectedComponents`/`LimitDepth` (bounded node/edge/depth
  limits — an unrelated pair of observations never end up in the same
  correlation), `ComputeFingerprint` (dedup key, same "truncate onto the
  window's grid" approach as Phase 11's), `Score`/`ConfidenceForScore`/
  `DeriveSeverity` (three distinct, documented axes — score is never
  described as a probability of attack), `BuildChain` (stage
  classification heuristic + evidence-weighted, non-averaged chain
  confidence), `Explain` (lists strategies/evidence/window/confidence,
  closes with a fixed non-attack disclaimer).
- `internal/correlation/strategies` — 6 built-in strategies: `asset`
  (same-asset, observed, high confidence), `temporal` (sliding-window
  proximity, inferred, low confidence), `identity` (this platform's
  no-login-model adaptation: authentication-category co-location),
  `network` (shared `Asset.IP`, cross-asset, inferred), `detection`
  (cross-rule chronological sequence on one asset), `intelligence`
  (indicator-value match, always labeled EXTERNAL, never observed
  activity).
- `internal/repository/correlation` + `migrations/000012_create_
  correlations.sql` — 5 tables (`correlations`, `correlation_nodes`,
  `correlation_edges`, `attack_chains`, `attack_chain_stages`); no
  separate `correlation_strategies`/`correlation_merges`/
  `correlation_splits` tables — strategy identity/version live on each
  edge, and merge/split lineage lives directly on `correlations` (a row
  is never deleted, so its own id already is the audit record).
- `internal/service/correlation` — the bridge: `buildObservations`
  (projects Phase 2/7/8/10/11 rows, resolving a `DetectionMatch`'s asset
  via its own evidence since the match row itself carries none),
  `Evaluate` (engine run → connected components → one `Correlation` per
  component → attack chain when classifiable), `Confirm`/`Dismiss`
  (analyst-only, reason/actor required), `Merge`/`Split` (transactional,
  evidence-preserving), `AttachToInvestigation` (Phase 9 integration,
  mirrors Phase 11's `PromoteToInvestigation`), `ExportCorrelation`
  (JSON/YAML, no secrets).
- `cmd/cli/commands/{correlation,chain}.go` — `ai-surface correlation
  list|show|evaluate|graph|timeline|evidence|confirm|dismiss|merge|
  split|investigate|export` and `ai-surface chain list|show|explain`.
- `correlation.*` top-level configuration section (`enabled`,
  `temporal.default_window`, `graph.{max_depth,max_nodes,max_edges}`,
  `workers.max_concurrency`, `historical_max_range`, `max_candidates`).
- Two small, additive extensions mirroring Phase 11's own pattern:
  `internal/domain/investigation` gains `EventCorrelationAttached`/
  `EventAttackChainCreated` timeline event types and
  `EntityCorrelation`/`EntityAttackChain` entity types; `internal/
  intelligence/risk` gains a documented `correlation` factor
  (`Input.OpenCorrelationCount`, `Weights.CorrelationOpen`/
  `CorrelationRepeatedPerCount`/`CorrelationRepeatedMax`), wired
  optionally via `intelligencesvc.Service.WithCorrelations` so Phase 10
  has no hard dependency on Phase 12.
- `docs/architecture/correlation-engine.md`, `docs/detection/
  correlation-strategies.md`, `docs/investigation/attack-chains.md`.
- 40 new tests (8 domain validation, 4 engine failure-isolation/
  determinism/truncation, 2 config bounds, 6 scoring/severity, 4 chain
  ordering/gaps/confidence-weighting, 3 fingerprint determinism/order-
  independence, 1 explanation safety, 4 graph dedup/limits/components,
  8 strategy behavior) + 4 benchmarks (1,000/10,000/100,000-observation
  engine correlation, fingerprint computation).

### Design notes

- **No raw event-ingestion pipeline, and no user/session/login model.**
  phase12.md's SIEM-shaped vocabulary (failed/successful login, network
  flow events) assumes infrastructure this reconnaissance platform never
  built. "Identity correlation" is adapted to authentication-category
  finding/detection co-location — the closest honest analog available;
  "network correlation" uses Phase 2's already-recorded `Asset.IP`,
  never a new scan.
- **No job/worker queue** — `cmd/worker` still has none (see its own doc
  comment, unchanged since Phase 1); `ai-surface correlation evaluate` is
  CLI-invoked, the same "CLI is the interface, no daemon" precedent every
  prior phase follows.
- **No REST API** — consistent with every phase since Phase 1; the CLI
  remains the sole interface.
- **No authentication/authorization/multi-tenancy RBAC** — `TargetID`
  scoping is the only isolation boundary, identical to every other
  entity since Phase 2.
- **`CorrelationNode` doubles as `CorrelationEvidence`** — a second table
  storing the same `(correlation_id, type, reference_id)` reference would
  itself be the duplication phase12.md's own "do not duplicate entire
  records" instruction warns against.
- **Merge/split lineage lives on `correlations` itself** — no separate
  `correlation_merges`/`correlation_splits` audit tables: a correlation
  row is never deleted, so its own id, `MergedIntoID`, and
  `SplitFromID` already form the permanent record.
- **No GraphML export** — phase12.md itself permits skipping it "if not
  useful"; JSON/YAML via `ai-surface correlation export` covers the
  documented need.
- **No second correlation engine, no second risk calculator** — Phase
  9's finding-pair correlation and Phase 10's risk scorer are reused and
  extended (one additive risk factor), never duplicated.
- **Three-level `Confidence` (low/medium/high)**, deliberately distinct
  from Phase 9's five-level `investigation.Confidence` and Phase 11's
  `rule.Confidence` — phase12.md §9/§32 both specify a coarser three-level
  scale for edges and for a correlation's overall confidence.

## Phase 11 — Detection Engineering & Rule Engine

### Added

- `internal/domain/rule` — `Rule` (identity/metadata, denormalized
  Severity/Confidence/RuleType kept in sync with its latest version),
  `Version` (immutable, versioned Definition + content hash, no Update
  path anywhere), `DetectionMatch` (fingerprint-deduplicated, evidence-
  backed, explained), `MatchEvidence`, `Alert` (references a match
  rather than duplicating its evidence), `Suppression` (never deleted —
  a removal sets `RemovedAt`/`RemovedBy`).
- `internal/ruleengine` — the self-contained rule engine: `Condition`/
  `Operator` (12 safe operators, no arbitrary expressions), `Definition`
  (4 rule types: `field_match`/`threshold`/`sequence`/`aggregation`),
  `Validator` (structured `rule.validation.*` errors), `Compile`/
  `NormalizedHash` (content-addressed, order-independent), `Engine.
  Evaluate` (deterministic, fixed-window threshold/aggregation, ordered-
  scan sequence detection), `ComputeFingerprint` (rule+version+group+
  normalized-window dedup key), `Explain` (human-readable, never "rule
  matched" alone), `ParseJSON`/`ParseYAML`/`EncodeJSON`/`EncodeYAML`
  (using the already-present `gopkg.in/yaml.v3` dependency), `RunTest`/
  `TestCase` (a dry-run rule-testing framework with zero database
  dependency).
- `internal/ruleengine/builtin` — 5 built-in rules (one per rule type,
  plus a second threshold example), each fully documented (purpose,
  logic, limitations, false-positive guidance) and carrying its own
  positive/negative/boundary regression suite.
- `internal/repository/rule` + `migrations/000011_create_rules.sql` — 6
  tables (`rules`, `rule_versions`, `detection_matches`,
  `detection_evidence`, `alerts`, `suppressions`); fingerprint-deduplicated
  match/alert upserts that never revert an analyst's status decision.
- `internal/service/rule` — the bridge: rule CRUD/versioning
  (`CreateRule`/`CreateVersion`/`Enable`/`Disable`/`Deprecate`),
  event-assembly (`events.go` — projects Phase 2/6/7/8/10 rows into
  normalized `ruleengine.Event` values, the one place this platform's
  "no raw log ingestion" boundary is bridged), `Evaluate` (persists
  matches, attaches evidence, applies suppression, upserts alerts),
  alert lifecycle (`AcknowledgeAlert`/`ResolveAlert`/`SuppressAlert`),
  `PromoteToInvestigation` (Phase 9 integration), `Import`/`Export`.
- `cmd/cli/commands/{detection,alert}.go` — `ai-surface detection
  list|show|create|edit|enable|disable|versions|export|import|evaluate|
  suppress|builtin(list/test/install)` and `ai-surface alert
  list|show|acknowledge|resolve|suppress|investigate`.
- `detection_rules.*` top-level configuration section (`enabled`,
  `evaluation.{max_concurrency,timeout,clock_skew}`,
  `suppression_default_window`, `historical.max_range`).
- Two small, additive extensions to existing Phase 9/10 models: Phase
  9's `internal/domain/investigation` gains `EventDetectionMatchCreated`/
  `EventAlertStatusChanged` timeline event types and
  `EntityDetectionMatch`/`EntityAlert` entity types (phase11.md §100/
  §101/§102's own hedge: "unless the existing model explicitly supports
  both" — it now does); Phase 10's `internal/intelligence/risk` gains a
  documented `detection_match` factor (`Input.OpenDetectionMatchCount`,
  `Weights.DetectionMatchOpen`/`DetectionMatchRepeatedPerCount`/
  `DetectionMatchRepeatedMax`), wired optionally via
  `intelligencesvc.Service.WithDetectionMatches` so Phase 10 has no hard
  dependency on Phase 11.
- `docs/architecture/detection-engine.md`, `docs/detection/rule-
  authoring.md`, `docs/detection/builtin-rules.md`.
- 41 new tests (6 domain validation, 34 engine — conditions/validator/
  compiler/engine/parser — plus 1 built-in-rule regression test that
  itself runs all 5 built-in rules' own positive/negative/boundary
  fixtures as subtests) + 4 benchmarks (1,000/10,000/100,000-event
  threshold evaluation, fingerprint computation).

### Design notes

- **This platform has no raw-log-ingestion pipeline, and Phase 11 does
  not add one.** phase11.md's own "Logs → Normalization → Events"
  workflow assumes infrastructure (log ingestion, authentication,
  authorization, a project model, a job system) this platform never
  built and this phase was explicitly directed not to add. "Events" are
  instead normalized projections of already-persisted Phase 2/6/7/8/10
  rows (findings, asset/endpoint observations, technology fingerprints,
  intelligence records) — never a duplicate event-log table.
- **"Project" maps to this platform's existing `Target`**, the same
  convention every prior phase established.
- **No authentication/authorization/multi-tenancy RBAC** — this
  platform has none in any phase; `TargetID` scoping is the only
  isolation boundary, identical to every other entity since Phase 2.
- **No scheduler/job system** — `ai-surface detection evaluate` is
  CLI-invoked; an operator wires external cron/CI for periodic
  evaluation if desired, the same "CLI is the interface, no daemon"
  precedent every prior phase follows.
- **Fixed, not sliding, windows** for threshold/aggregation evaluation —
  phase11.md §43 explicitly permits either; fixed was chosen for
  determinism and to avoid a combinatorial number of overlapping
  near-duplicate matches for one sustained pattern.
- **No second correlation engine** — a promoted alert's evidence feeds
  directly into Phase 9's existing correlation engine once attached to
  an investigation; Phase 11 does not reimplement correlation.
- **No second risk calculator** — Phase 10's model gained one additive,
  documented factor rather than a parallel scoring system.

## Phase 10 — Threat Intelligence & Risk Enrichment Engine

### Added

- `internal/domain/intelligence` — `IntelligenceRecord` (provenance-
  tagged provider observation: `ProviderID`/`ProviderVersion`,
  `SourceType`, `Category`, `Verdict`, leveled `Confidence`, TTL
  `Expiration`), `VulnerabilityRecord`/`VulnerabilityMatch` (`MatchStatus`
  `confirmed`/`probable`/`insufficient_evidence`/`no_match`, `ValidCVE`
  format check), `RiskScore`/`RiskFactor` (append-only history,
  `ModelVersionV1`), `EnrichmentEvent` (9 event types), `AssetCriticality`
  (analyst-set, never inferred).
- `internal/intelligence` — the self-contained engine: `Provider`
  interface, `Registry` (runtime enable/disable + per-provider health
  tracking), `Engine.Lookup`/`Plan` (per-provider error isolation, cache-
  before-fetch, external-provider opt-in gating), indicator
  normalization, `Cache` interface + `MemoryCache`, `DedupRecords`,
  `Aggregate` (multi-source, conflict-preserving, majority-vote-with-
  conservative-tiebreak reputation aggregation), `Matcher`/`CatalogEntry`
  (version-constraint vulnerability matching with a self-contained
  dotted-numeric comparator — no new third-party dependency).
- `internal/intelligence/providers` — `LocalProvider`/`DNSProvider`/
  `CertificateProvider`/`TechnologyProvider` (zero external dependency,
  always report `VerdictUnknown` — descriptive context, never an
  inferred verdict) and `ThreatFeedProvider` (the one external, opt-in,
  rate-limited, Retry-After-respecting provider; no vendor hard-coded).
- `internal/intelligence/risk` — `Scorer`/`Weights`/`Input`/`Factor`: a
  deterministic 0-100 score, clamped, fully explained, versioned
  (`ModelVersion = "v1"`) — see `docs/security/risk-model-v1.md`.
- `internal/repository/intelligence` + `migrations/000010_create_
  intelligence.sql` — 7 tables (`intelligence_records`,
  `intelligence_cache`, `vulnerability_records`, `vulnerability_matches`,
  `risk_scores`, `enrichment_events`, `asset_criticality`); Postgres-
  backed persistent cache exposed to the engine via a byte-level
  `CacheRepository` (repository never imports the engine package).
- `internal/service/intelligence` — bridges the engine to persistence:
  `Enrich`/`Show`/`Refresh`/`Plan` for indicator-level lookups,
  `EnrichAsset`/`EnrichFinding`/`EnrichInvestigation` (technology
  fingerprint → vulnerability match → risk score pipeline),
  `SetCriticality`, `RiskHistory`/`LatestRisk`, verdict-change and
  risk-increase `EnrichmentEvent` emission.
- `cmd/cli/commands/intel.go` + `risk.go` — `ai-surface intel
  lookup|enrich|refresh|providers|status|enrich-project` and `ai-surface
  risk asset|finding|investigation|criticality`.
- `intelligence.*` top-level configuration section (`enabled`,
  `external.enabled`, `providers` enable/disable map, `provider_timeout`,
  `reputation_ttl`/`vulnerability_ttl`, `threat_feed.*`, `risk.weights`).
- `docs/architecture/threat-intelligence.md`,
  `docs/security/risk-model-v1.md`.
- Unit tests across `internal/domain/intelligence`, `internal/
  intelligence`, and `internal/intelligence/risk` (normalization,
  registry, cache hit/miss, provider-failure isolation, external opt-in
  gating, conflict-preserving aggregation with an explicit "never
  auto-confirm malicious" test, vulnerability match status coverage
  including the "product name alone is never a match" guardrail, and
  risk-model determinism/clamping/severity-boundary/history coverage),
  plus 6 benchmarks at 10,000/50,000-scale synthetic data.

### Design notes

- **The vulnerability catalog ships empty.** phase10.md §13 forbids
  generating a CVE or guessing version applicability; rather than seed
  potentially-inaccurate CVE data, `Matcher` is fully implemented and
  tested against a synthetic catalog, and a real catalog is an operator/
  future-feed responsibility (phase10.md §12's own "should support future
  external feeds").
- **Local providers never report a verdict.** `LocalProvider`/
  `DNSProvider`/`CertificateProvider`/`TechnologyProvider` always return
  `VerdictUnknown` — this platform has no reputation database of its
  own, and synthesizing "suspicious"/"malicious" from local observations
  alone would be exactly the unsupported threat inference phase10.md
  §101 prohibits. Only the opt-in external `ThreatFeedProvider` can ever
  report a non-unknown verdict.
- **`providers.DatasetSource`: a mutable dataset holder, not a per-
  provider constructor argument.** One `Registry`/`Engine` pair is built
  once per CLI invocation but must serve many different assets/
  indicators within that run; the service updates the shared source
  before each lookup that needs local data. Documented as safe for this
  project's single-invocation CLI model, not a concurrent server.
- **No REST API layer**, consistent with every prior phase (Phase 2-9
  ship no HTTP API for findings/investigations either) — the CLI remains
  this project's primary interface throughout.
- **No integration test suite this phase.** `test/integration/` and
  `test/fixtures/` were removed earlier in this same session at the
  user's explicit, one-time request; rebuilding that harness was out of
  scope here — see `docs/architecture/threat-intelligence.md`'s Known
  Limitations.
- **"Project" maps to this platform's existing `Target`**, the same
  convention Phase 8/9 established — `IntelligenceRecord`/`RiskScore`/
  etc. all carry `TargetID`, never a separate `ProjectID`.

## Phase 9 — Investigation & Incident Correlation Engine

### Added

- `internal/domain/investigation` — `Investigation` (case management:
  Status/Priority/Severity/Confidence, optimistic-concurrency `Version`,
  incident-facing `DetectedAt`/`FirstObservedAt`/`LastObservedAt` widened
  only from real evidence), `EvidenceRef` (finding/asset/endpoint/scan
  reference with `RelationType` and full provenance), `TimelineEvent`
  (25 event types spanning both real-observation history and the
  investigation's own audit trail), `Relationship` (typed, scored,
  explained correlation edge with `candidate`/`confirmed` status),
  `Hypothesis`/`HypothesisEvidence`, `Note` (immutable), `IncidentCluster`/
  `ClusterItem` (suggested/accepted/rejected).
- `internal/investigation` — the self-contained correlation engine:
  `Rule` interface, `Registry` (runtime enable/disable, versioning),
  `Engine.Correlate` (per-rule error isolation, same-key merge),
  `Input`/observation types built entirely from already-persisted Phase
  2/6/7/8 data, `ConfidenceForScore` (documented score→confidence
  bucketing).
- `internal/investigation/correlation` — 8 built-in rules across 8 files:
  `same_asset_findings`, `same_endpoint_findings`, `temporal_proximity`,
  `technology_correlation`, `same_service` (deliberately low-scored —
  "same IP" is never sufficient alone, phase9.md §39), `endpoint_change_
  with_finding`, `authentication_colocation`, `new_asset_with_finding` —
  every relationship carries an explicit explanation and its contributing
  signals, never a bare boolean.
- `internal/repository/investigation` + `migrations/000009_create_
  investigations.sql` — 9 tables (`investigations`, `investigation_
  evidence`, `timeline_events`, `investigation_relationships`,
  `hypotheses`, `hypothesis_evidence`, `investigation_notes`,
  `incident_clusters`, `incident_cluster_items`); optimistic-concurrency
  `Update` (version-checked); idempotent relationship upsert.
- `internal/service/investigation` — case-management CRUD/lifecycle
  (create/update/close/reopen with required-reason reopen), evidence
  attachment (with finding-history timeline materialization), timeline,
  correlation orchestration (dry-run supported), hypotheses, notes,
  incident-cluster suggestion/accept/reject, automatically-generated
  summary (dashboard view model), JSON/CSV/Markdown export.
- `cmd/cli/commands/investigate.go` — `ai-surface investigate
  create|list|show|timeline|correlate|findings|attach|note|hypothesis|
  close|reopen|export|cluster` (suggest/list/accept/reject).
- `investigation.*` top-level configuration section (`enabled`,
  `correlation.enabled`, `correlation.threshold`, `correlation.
  temporal_window`, `correlation.rules` enable/disable map).
- `docs/architecture/investigation-engine.md`.
- 85 new tests (domain validation, engine isolation/dedup/config, all 8
  correlation rules including explicit false-correlation guardrail tests,
  service-layer pure helpers, export rendering) plus 2 correlation-scale
  benchmarks and a 6-test integration suite (`test/integration/
  investigation_persistence_test.go`) covering end-to-end create→attach→
  correlate, dry-run persisting nothing, close/reopen lifecycle,
  optimistic-concurrency conflict detection, notes/hypotheses, and
  cluster suggest→accept.

### Design notes

- **Incident = Investigation, one entity.** phase9.md §3's "Incident"
  fields are almost a strict subset of Investigation's own (§2); rather
  than duplicate the table/entity, `Investigation` carries every field
  either section asks for — the consolidation phase9.md §54 itself
  sanctions. Documented once, in `internal/domain/investigation`'s
  package doc comment.
- **Timeline doubles as audit trail.** phase9.md §61's required audit
  actions map directly onto `TimelineEvent`'s own event vocabulary — a
  second, separate `audit_log` table would only create two sources of
  truth for "what happened to this investigation."
- **"Project" maps to this platform's existing `Target`**, the same
  mapping Phase 8's report established — no separate Project entity
  exists anywhere in this codebase.
- **Deliberately weak signals stay weak.** `same_service` (shared IP) and
  `temporal_proximity` alone can never cross the default confirm
  threshold — verified directly by dedicated tests — per phase9.md §39's
  explicit "same IP = same incident" false-correlation warning.
- **Automatic grouping only ever suggests.** `SuggestClusters` never
  creates or merges an Investigation on its own; every cluster starts
  `suggested` and requires an explicit analyst `Accept` (phase9.md §40).
- **No REST API.** None exists anywhere in this project yet; Phase 9
  follows the same decision Phase 6/7/8 already made.

## Phase 8 — Finding & Vulnerability Detection Engine

### Added

- `internal/domain/finding` — the `Finding`/`Evidence`/`Event` domain
  model (mirroring Asset/Endpoint/Fingerprint's shape): deterministic
  identity (`target + asset + detector [+ endpoint]`), independent
  severity/confidence axes, five-state lifecycle
  (`open`/`resolved`/`reopened`/`accepted_risk`/`false_positive`),
  human severity override that never destroys the detector's own output.
- `internal/detection` — the self-contained detection engine: `Detector`
  interface, `Registry` (runtime enable/disable, versioning, metadata),
  `Engine.Evaluate` (per-detector error isolation, confidence clamping,
  identity-based dedup merge), `Input`/observation types built entirely
  from already-persisted Phase 2-7 data, `SafeActiveFetcher` +
  `HTTPFetcher` (reuses `internal/httpclient.Client`, zero new transport),
  pure lifecycle/diff classification (`NextStatus`, `ClassifyChange`).
- `internal/detection/detectors` — 22 built-in detectors across 13 files:
  HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy,
  cookie security (Secure/HttpOnly/SameSite, names/attributes only),
  CORS wildcard+credentials, TLS certificate expiration, obsolete TLS
  protocol, information disclosure (version-bearing headers only),
  sensitive open service ports, sensitive-shaped endpoint paths, backup
  files, exposed `.git/HEAD` and `.env` (key names only, values never
  stored), missing `security.txt`, error/stack-trace disclosure,
  directory listing, exposed API documentation, GraphQL inventory,
  documented-but-unobserved HTTP methods, authentication-surface
  inventory, and a technology-vulnerability detector backed by an empty-
  by-default `VulnerabilityCatalog` (no hardcoded CVE data — see Design
  notes).
- `internal/repository/finding` + `migrations/000008_create_findings.sql`
  — `findings` (current state, upserted, MIN/MAX first/last-seen),
  `finding_evidence` (append-only, deduplicated by fingerprint), and
  `finding_events` (append-only lifecycle audit trail, queryable by
  scan id for `findings diff`).
- `internal/service/detection` — assembles `Input` from Phase 2/3/4/6/7's
  already-persisted assets/endpoints/TLS-service-observations/
  fingerprints, evaluates, and persists with historical lifecycle
  tracking; enforces target authorization for safe-active mode only.
- `cmd/cli/commands/findings.go` — `ai-surface findings scan|list|show|diff`
  (table/JSON/CSV output, dry-run, severity/category/status/detector
  filters).
- `detection.*` top-level configuration section (`enabled`, `mode`,
  `detectors` enable/disable map, `evidence.max_excerpt_size`,
  `thresholds.certificate_expiry_days`, safe-active `timeout`/
  `max_response_size`).
- `docs/architecture/finding-detection.md`.
- Comprehensive unit tests (engine, registry, lifecycle, diff, dedup,
  every detector including all 5 safe-active ones via a scripted fake
  fetcher, service-layer pure helpers) and a 6-test integration suite
  (`test/integration/finding_persistence_test.go`) covering end-to-end
  persistence, the full open→resolved→reopened lifecycle, dry-run
  persisting nothing, safe-active authorization enforcement, passive
  mode requiring no authorization, and a real safe-active git-exposure
  check against a local `httptest` fixture.

### Design notes

- **Passive-by-default, explicit safe-active.** Every detector declares
  `Mode() == passive` or `safe_active`; `Registry.Active(mode)` excludes
  safe-active detectors entirely unless the caller explicitly requested
  safe-active mode, which additionally requires the target be
  `AUTHORIZED` — the same boundary Phase 3/7 already enforce for active
  discovery. Passive analysis performs no request of its own and is
  therefore not gated by authorization, mirroring Phase 6's fingerprint
  command exactly.
- **Two minimal, well-justified Phase 3/4 extensions**, both following
  the same "extend, never duplicate" precedent Phase 6/7 established:
  cookie *attribute* capture (`cookie_attributes` metadata key — Secure/
  HttpOnly/SameSite only, never a value, extracted from the same raw
  pre-redaction headers `cookie_names` already reads) and TLS certificate
  `NotAfter` persistence (`certificate_not_after`, from data Phase 4's
  `probeTLS` already captured in-memory but never previously wrote to
  metadata). A pre-existing test (`TestSanitizeMetadata_RecursesIntoArrays`)
  caught a real naming collision during development — see Errors Found
  and Fixed in `doc_by_me/reports/phase8-report.md`.
- **No REST API added.** No resource-level REST API exists anywhere in
  this project yet (Phase 1's `internal/httpserver` only exposes
  `/health`/`/ready`); Phase 8 follows every prior phase's decision not
  to add one either.
- **Empty `VulnerabilityCatalog` by default.** The technology-
  vulnerability detector, its semver-range matching (via
  `github.com/Masterminds/semver/v3` — the one new dependency this phase
  adds), and its full test suite all exist and are exercised, but the
  catalog ships with zero entries — this project never hardcodes CVE data
  or guesses a CVE identifier (§41/§89).
- **`findings diff` reads its own audit trail, never re-runs detection.**
  Each detection run stamps every lifecycle transition's `finding_events`
  row with that run's `scan_id`; `findings diff --scan <id>` reconstructs
  RESOLVED/PERSISTING/REOPENED/NEW purely from those rows — no point-in-
  time state reconstruction needed.
- **"Project" maps to this platform's existing `Target`.** The spec's
  Finding-model field `ProjectID` is implemented as `TargetID`, consistent
  with every other domain object in this codebase (Asset, Endpoint,
  Fingerprint all key off `TargetID`, and there is no separate `Project`
  entity anywhere in the platform).

## Phase 7 — Endpoint & API Discovery Engine

### Added
- `internal/discovery/endpoint`: the endpoint/API discovery engine — a
  bounded, breadth-first `Crawler` (depth/page/endpoint/response-size/
  concurrency/rate limits, cycle-safe visited tracking, context
  cancellation throughout), `Classify` (page/api/graphql/openapi/
  swagger/auth/static/documentation/sitemap/robots/websocket_candidate/
  unknown classification plus API type/version detection),
  `TemplatePath` (conservative dynamic-path-segment templating —
  `/users/123` and `/users/456` collapse to `/users/{id}`, `/users/admin`
  does not), `ParseHTML` (link/form static extraction via
  `golang.org/x/net/html`, no script execution), `ExtractJSRoutes`
  (static JavaScript route extraction with two confidence tiers —
  `fetch()`/`axios()`/`.open()` call sites at 0.75, bare path-shaped
  string literals at 0.30), `ParseOpenAPI` (OpenAPI 3.x and Swagger 2.0,
  JSON and YAML, extracting paths/methods/operationIds/tags/parameter
  names/content types/authentication-mechanism *types* only — never
  credentials), `ParseRobots`/`ParseSitemap` (robots.txt is never an
  authorization boundary — a Disallow entry is an ordinary candidate;
  sitemap index recursion is bounded and cycle-protected), and an
  `accumulator` that merges every source's contribution to the same
  logical endpoint (one endpoint with `sources: [html, javascript,
  openapi]`, never three separate rows).
- `internal/discovery/service/{endpoint,endpoint_persist}.go`: extends
  the existing Phase 3/4/5/6 `Service` (not a parallel orchestrator) with
  `RunEndpoint` — seed resolution from the target's own known HTTP(S)
  assets (https preferred over http), the same authorization → scope →
  scan → persist shape, and endpoint change detection
  (added/removed/parameter_added/parameter_removed/
  classification_changed/api_version_changed/status_changed — a status
  change is never reported as removed, phase7.md §45).
- Extended (never duplicated) the existing Phase 2 `Endpoint` model
  (`internal/domain/endpoint`) with `ScanID`, `ContentLength`,
  `Classification`, `APIType`, `APIVersion`, `Sources`, `Confidence`, and
  the independent, non-exclusive `Documented`/`Observed`/`Inferred`
  facts (phase7.md §46/§47) — endpoint identity itself
  (`asset_id, method, normalized url`) is unchanged, since Phase 2's
  existing `Normalize` already satisfies Phase 7's normalization/identity
  requirements in full (hostname casing, default ports, dot segments,
  trailing slash, fragment removal, query-parameter-name-only retention).
- `migrations/000007_extend_endpoints.sql`: extends `endpoints` (ALTER
  TABLE, not a new table) with the fields above, plus two new tables —
  `endpoint_evidence` (append-only, mirrors `asset_evidence`/
  `fingerprint_evidence` exactly) and `endpoint_parameters` (parameter
  *names* only, never values, with a `location` of query/path/form).
- `Config.Discovery.Endpoint` (`internal/config`): enabled, timeout,
  concurrency/rate limits, depth/page/endpoint/response-size limits,
  per-source enable toggles (robots/sitemap/javascript/openapi),
  sitemap-recursion limits, seed paths, a configurable sensitive-
  parameter-name list, and named profiles (`quick`, `standard`,
  `comprehensive`).
- `cmd/cli endpoint-scan`: `ai-surface endpoint-scan --target <target>
  [--seed] [--depth] [--max-pages] [--max-endpoints] [--timeout]
  [--concurrency] [--requests-per-second] [--format table|json]
  [--profile] [--dry-run]`. Only ever sends GET requests; never submits a
  discovered form.
- `test/fixtures/endpoint`: a fully local, offline HTTP fixture (HTML
  links including duplicates and a cyclic link graph, a login form,
  JSON API responses, an OpenAPI document, a Swagger document,
  robots.txt, sitemap.xml, JavaScript with real API-call and weak-string
  references, a redirect, an external-domain reference, dynamic-ID
  paths, and a query-parameter endpoint).
- Unit tests across every new file in `internal/discovery/endpoint`
  (URL/path templating, HTML parsing including "never captures form
  values", JavaScript extraction confidence tiers and no-double-counting,
  OpenAPI/Swagger JSON+YAML parsing, robots/sitemap parsing including
  bounded-recursion and malformed-input cases, classification, and 17
  end-to-end crawler tests: HTML link discovery, duplicate-link dedup,
  cyclic-link termination, form-discovered-never-submitted, JavaScript
  extraction, OpenAPI discovery with the documented-vs-observed
  distinction proven directly, robots/sitemap, in-scope redirect
  following, external-link scope rejection, dynamic-path templating,
  query-parameter recording, depth/page/endpoint/response-size limits,
  scope rejection, and context cancellation). `go test -race ./...`
  passes repository-wide (one real data race — an unlocked read of a
  shared page-budget counter from the crawl-dispatch loop racing against
  locked writes from worker goroutines — was found and fixed during this
  phase's own verification, the same "test yourself, don't just claim it
  works" discipline every prior phase followed). Benchmarks measure URL
  normalization, path templating, HTML parsing, JS extraction, OpenAPI
  parsing, and multi-source endpoint-merging throughput — no network I/O.
  Integration tests (`test/integration/endpoint_persistence_test.go`,
  real PostgreSQL): end-to-end asset/endpoint/parameter persistence with
  the documented+observed distinction verified against real crawl output,
  idempotent re-scan, added-change detection across two scans of
  different pages, unauthorized-target refusal, and dry-run (nothing
  requested or persisted).
- `docs/architecture/endpoint-discovery.md`: full Phase 7 architecture
  writeup with a Mermaid diagram.

### Design notes
- **No new HTTP transport, scope mechanism, or asset-tracking system.**
  The crawler is built directly on `internal/httpclient.Client` (via the
  same `AllowRedirectTo` extension point Phase 3 introduced) and
  `internal/discovery/http.ScopeValidator`, reused unmodified — the
  identical "reuse Phase 3's scope for anything hostname-shaped, do not
  invent a second mechanism" decision Phase 5 made for DNS discovery.
- **No REST API endpoints added**, consistent with Phase 6's own
  decision: no asset/target/scan REST API exists for any resource yet in
  this platform (`internal/httpserver` still serves only `/health`/
  `/ready`).
- **`method_added`/`method_removed` are not separate change types** —
  since endpoint identity already includes `Method`, a new method for an
  existing path surfaces as an ordinary `added` change at that specific
  `(method, url)` identity, unambiguous without a second, path-grouped
  comparison pass.

## Phase 6 — Passive Fingerprinting & Technology Identification Engine

### Added
- `internal/fingerprint`: the self-contained, no-database-dependency
  matching engine — `Category`/`SignalType`/`Level`/`Thresholds`,
  `Observation` (the engine's sole input, assembled entirely from
  already-persisted data), `Signature`/`SignalRule` (declarative YAML
  schema — no hardcoded switch statement), `LoadSignatures`/
  `LoadDefaultSignatures` (validates name/category/signals/regex/weight/
  duplicate-name/signal-type at load time, fails clearly, never silently
  skips), `NormalizeTechnology` (a small, explicit alias table — never
  fuzzy matching), `matchSignature`/`score` (deterministic matching with
  duplicate-evidence dedup and ratio-based, transparent confidence
  scoring), and `Engine.Evaluate` (ties matching + scoring + declared-
  incompatibility conflict resolution + normalization together,
  deterministic output order). ~35 built-in signatures across all 20
  categories (`internal/fingerprint/signatures/*.yaml`), embedded via
  `go:embed`.
- `internal/domain/fingerprint`: the persisted model —
  `Fingerprint`/`Evidence`/`Signal`, mirroring `internal/domain/asset`'s
  shape deliberately, with its own `Score`/`Level` type (fingerprint
  evidence strength, never conflated with asset-existence confidence).
- `internal/repository/fingerprint` + `migrations/
  000006_create_fingerprints.sql`: `fingerprints` (current state, one row
  per asset+category+technology identity, upserted) and
  `fingerprint_evidence` (append-only historical trail, deduplicated by
  signal-set fingerprint) — mirroring `assets`/`asset_evidence`'s
  current-state/historical-trail duality exactly, including the same
  index set (asset, target, technology, category, scan, confidence,
  status).
- `internal/service/fingerprint`: bridges the engine to persistence —
  builds an `Observation` from real `Asset.Metadata` (the "latest
  snapshot" convention Phase 5 established), sibling assets sharing the
  same hostname (correlating DNS + network + HTTP layers for one logical
  site), and discovered `Endpoint` paths; persists every matched result
  transactionally (fingerprint + evidence, atomic); marks a fingerprint
  that stopped matching `INACTIVE` rather than deleting it; and detects
  `added`/`removed`/`version_changed`/`confidence_changed` (above a
  configurable threshold — minor fluctuations are never reported)
  relative to the asset's previous analysis.
- `Config.Fingerprint` (`internal/config`): enabled, signatures_path,
  min_confidence, confidence_change_threshold, configurable score
  thresholds, historical_tracking/detect_changes/redact_sensitive_data
  toggles — all YAML/env configurable.
- `cmd/cli fingerprint`: `ai-surface fingerprint --target <target> |
  --asset <asset-id> [--scan] [--format table|json] [--min-confidence]
  [--category] [--explain] [--dry-run]`. Never performs a network/DNS
  request itself, even when invoked.
- A small, additive Phase 3 extension (necessary for fingerprinting to
  have real header/cookie data to analyze — previously only the bare
  `Server` header value was captured): `model.Result` gained
  `CookieNames []string` (extracted from the raw, pre-redaction Set-
  Cookie header — names only, never values), and HTTP persistence gained
  a curated, closed allow-list of ~24 additional safe response headers
  (`X-Powered-By`, `Via`, `CF-Ray`, rate-limit headers, ...). A narrow,
  exact-match exception (`cookie_names`) was added to
  `internal/domain/asset`'s redaction boundary so this specific,
  deliberately-safe field isn't swallowed by the existing "any key
  containing 'cookie'" substring rule — `Set-Cookie`/`Cookie` themselves
  remain fully redacted, unaffected.
- Unit tests: `internal/fingerprint/*_test.go` (signature loading and
  every required validation failure; matching including conflict
  handling, coexisting technologies, corroboration, duplicate-evidence
  dedup, weak-vs-strong AI/database candidates, explicit model
  identifiers, determinism; scoring/threshold bucketing; normalization),
  `internal/domain/fingerprint/*_test.go`, `internal/service/
  fingerprint/service_test.go` (change detection, observation assembly),
  plus new tests for the Phase 3 extension
  (`internal/discovery/http/response_test.go`,
  `internal/domain/asset/redact_test.go`). A benchmark
  (`BenchmarkEngine_Evaluate_{10,100,1000}Assets`) measures pure in-
  memory matching throughput — no I/O. `go test -race ./...` passes
  repository-wide. Integration tests
  (`test/integration/fingerprint_persistence_test.go`, real PostgreSQL,
  against a real Phase 3 scan of a local fixture — not a hand-built
  `Observation`): end-to-end persistence, idempotent re-analysis,
  version-change detection with historical evidence preservation,
  removed-fingerprint handling (`INACTIVE`, never deleted), dry-run, and
  no-evidence-produces-no-fingerprints.
- `docs/architecture/fingerprinting.md`: full Phase 6 architecture
  writeup with a Mermaid diagram.

### Design notes
- **No REST API endpoints added.** The platform has no asset/target/scan
  REST API at all yet (`internal/httpserver` serves only `/health`/
  `/ready`) — adding fingerprint-only CRUD/read endpoints would invent a
  new architectural precedent rather than reuse an existing one.
  `Service.List`/`ListEvidence` exist and are ready to wire into
  whichever future phase adds the platform's first real API surface.
- **HTML-based signal types (`html`, `html_meta`, `script`, `stylesheet`,
  and `json_structure` beyond its special-cased `model` field) have no
  real backing data today** — Phase 3 deliberately never retains response
  bodies. Every signature relying on them (Next.js, React, Vue.js,
  Angular, WordPress's generator meta, Drupal's path marker) is fully
  implemented and tested against synthetic fixtures, stated plainly as
  not yet fed by real evidence rather than left to be discovered.
- Database/service "candidate" signatures are deliberately capped at
  ~0.25 confidence from a port number alone — each declares a second,
  stronger corroborating signal (a product-specific service
  classification) that Phase 4's current port classifier doesn't yet
  produce; this is the ratio-based scoring model's natural, intended
  consequence of declaring evidence this phase can't yet supply, not a
  workaround.

## Phase 5 — DNS & Subdomain Discovery Engine

### Added
- `internal/discovery/dns`: the DNS discovery engine — `NormalizeName`/
  `JoinLabel` (deterministic, IDNA-aware name normalization), `Resolver`
  (interface over `github.com/miekg/dns`, with `NewExplicitResolver`/
  `NewSystemResolver` constructors), `RecordType`/`Record` (all 8 forward
  types plus PTR, with `Identity()`/`Fingerprint()` deliberately excluding
  TTL), `ResolutionState`/`classify`/`classifyTransportError`
  (RESOLVED/NXDOMAIN/NO_ANSWER/TIMEOUT/ERROR — never collapsed together),
  `GenerateCandidates`/`LoadWordlist` (deterministic, deduplicated,
  depth- and count-capped subdomain candidate generation),
  `DetectWildcard`/`MatchesWildcard` (multi-probe wildcard baseline,
  distinguishing genuine distinct records from wildcard noise),
  `SanitizeTXTValue` (content-level, not just key-level, secret redaction
  for TXT record text), and `Scanner` (bounded-concurrency record +
  subdomain + reverse-PTR resolution, optional rate limiting, scope
  filtering).
- `internal/discovery/service/dns.go`: extends the existing Phase 3/4
  `Service` (not a parallel orchestrator) with `RunDNS` — the same
  authorization → scope → scan → persist shape, persisting DOMAIN/
  SUBDOMAIN/IP assets and DNS_RECORD evidence through the same
  `AssetService`. Scope reuses Phase 3's `http.ScopeValidator` directly
  (the semantically correct concept for a domain, unlike Phase 4's
  necessary non-reuse for IP/CIDR).
- `Config.Discovery.DNS` (`internal/config`): enabled, timeout,
  concurrency/rate limits, explicit resolver list, record types, reverse-
  PTR toggle, subdomain settings (wordlist, max candidates, max depth,
  wildcard detection toggle), and named profiles (`quick`, `standard`,
  `comprehensive`) with a per-profile `max_depth` override — all YAML/env
  configurable.
- `cmd/cli dns-scan` / `cmd/cli subdomain-scan`: `ai-surface dns-scan
  --target <target> [--record-types] [--subdomains] [--wordlist]
  [--max-candidates] [--max-depth] [--profile] [--format table|json]
  [--timeout] [--concurrency] [--rate] [--resolvers] [--dry-run]`;
  `subdomain-scan` is a thin alias with enumeration always on.
  `cmd/cli target authorize` is reused unchanged — Phase 5 adds no second
  authorization command.
- `github.com/miekg/dns` and `golang.org/x/net/idna` added as
  dependencies — Go's stdlib `net.Resolver` cannot express SOA/CAA
  structured records, TTL, or protocol-level rcodes (NXDOMAIN vs. SERVFAIL
  vs. NODATA), which this phase requires.
- `test/fixtures/dns`: a fully local, offline authoritative-style UDP DNS
  server (deterministic zone: A/AAAA/CNAME/MX/NS/TXT/SOA/CAA records, a
  wildcard domain with a distinct override, PTR entries, a deliberately
  absent NXDOMAIN name) with live mutation support (`SetRecords`/
  `SetWildcard`, used to simulate a DNS change between scans) plus a
  standalone `cmd/dnsserver` binary for manual testing.
- `docs/architecture/dns-discovery.md`: full Phase 5 architecture writeup
  with a Mermaid diagram.
- Unit tests (`internal/discovery/dns/*_test.go`): name normalization
  (including IDN conversion and invalid-label rejection), record identity/
  fingerprinting (including TTL exclusion from both), every record type's
  parsing against the real local fixture (including SOA/CAA structured
  fields), NXDOMAIN/NODATA/SERVFAIL/timeout/cancellation each asserted as
  distinct resolution states, candidate generation (depth, dedup,
  max-candidates cap, determinism), wildcard detection (including the
  "distinct record under a wildcard domain" case), scope filtering
  (in-scope vs. out-of-scope), TXT secret redaction, and profile/max-depth
  resolution precedence. A benchmark (`BenchmarkScanner_Scan`,
  `BenchmarkGenerateCandidates`) measures throughput against the local
  fixture only. `go test -race ./...` passes repository-wide, including
  under `-tags=integration`. Integration tests
  (`test/integration/dns_persistence_test.go`, real PostgreSQL): end-to-end
  persistence, re-scan `FirstSeen`/`LastSeen` dedup with zero new evidence
  rows for an unchanged record, historical evidence preservation across a
  simulated DNS record change (old value's evidence kept, new value's
  evidence added), wildcard-noise exclusion from persisted subdomains,
  scope enforcement, TXT secret redaction in persisted evidence,
  unauthorized-target refusal, dry-run (nothing persisted/queried), and a
  large-wordlist test confirming the `max_candidates` ceiling is never
  exceeded.

### Fixed (found via manual testing, before any user-facing release)
- **Combinatorial subdomain explosion at default depth**: a single shared
  `max_depth` setting (default 3, no per-profile override) made
  `dns-scan --profile quick` against a 5-word list produce 155 candidates
  instead of 5, contradicting the `quick` profile's "narrow, fast" intent.
  Fixed by adding a per-profile `MaxDepth` override (`0` = inherit the
  base setting) to `config.DNSProfileConfig`, setting `quick`/`standard`
  to depth 1 and `comprehensive` to depth 2, and wiring an explicit
  `--max-depth` CLI flag that wins over both. The profile-less base case
  had the identical bug (84 candidates from a 4-word list instead of 4);
  fixed by lowering the base `subdomains.max_depth` default itself from 3
  to 1 — the same "conservative by default" philosophy every other
  phase's defaults already follow. Re-verified after the fix: `quick` on
  a 5-word list produces exactly 5 candidates; a profile-less
  `subdomain-scan` with a 4-word list produces exactly 4.
- DNS evidence excludes both `scan_id` **and TTL** from the fingerprinted
  evidence data from the start — applying Phase 3's scan_id lesson
  proactively, plus a DNS-specific extension (TTL naturally counts down
  even when the underlying answer hasn't changed, which would otherwise
  cause the same "every re-scan creates a new evidence row" bug through a
  different field). Confirmed by re-scanning an unchanged fixture zone
  against a live database and observing the evidence count hold constant,
  then modifying the fixture's A record and confirming exactly one new
  evidence row is added while the original is preserved, never
  overwritten.

## Phase 4 — Network Discovery Engine

### Added
- `internal/discovery/network`: the TCP connect discovery engine —
  `ParsePorts` (single/list/range/mixed, deduplicated, sorted, never
  silently corrects malformed input), `ExpandTarget`/`SupportedTargetType`
  (HOST/IP as-is, CIDR expansion with documented network/broadcast
  exclusion and a `max_hosts` limit), `ScopeChecker` (address-membership
  scope — deliberately not a reuse of Phase 3's hostname/subdomain
  `ScopeValidator`, which would be semantically wrong for IP/CIDR),
  `classifyPort`/`httpCandidate`/`aiServiceCandidate` (conservative,
  port-number-only classification and candidate flagging), and `Scanner`
  (bounded-concurrency `net.Dialer`-based TCP connect, optional rate
  limiting, optional bounded TLS metadata probing for HTTPS/TLS_SERVICE
  candidates).
- `internal/discovery/service/network.go`: extends the existing Phase 3
  `Service` (not a parallel orchestrator) with `RunNetwork` — the same
  authorization → scope → scan → persist shape, persisting through the
  same `AssetService` as HTTP discovery.
- `Config.Discovery.Network` (`internal/config`): enabled, connect
  timeout, concurrency/rate/host limits, HTTP/AI candidate port lists, and
  named profiles (`quick`, `standard`, `comprehensive`) — all YAML/env
  configurable.
- `cmd/cli network-scan`: `ai-surface network-scan --target <target>
  [--ports | --profile] [--target-type] [--format table|json] [--timeout]
  [--concurrency] [--rate] [--dry-run]`. `cmd/cli target authorize`
  (Phase 3) is reused unchanged — Phase 4 adds no second authorization
  command.
- `test/fixtures/tcp`: a fully local, offline generic TCP fixture (accepts
  and closes connections, no protocol spoken) plus a `ClosedPort` helper.
  `test/fixtures/localenv`: a standalone binary starting the full local
  test environment (HTTP fixtures on :8000/:8080, TCP fixture on :9000)
  for manual verification.
- `docs/architecture/network-discovery.md`: full Phase 4 architecture
  writeup with a Mermaid diagram.
- Unit tests (`internal/discovery/network/*_test.go`): port parsing, CIDR/
  host/IP expansion (including the /30, /31, /32 boundary cases and the
  host-limit rejection), scope membership, service/AI candidate
  classification, and scanner behavior (open/closed/timeout/connection-
  failure states, bounded concurrency and cancellation — both verified via
  a dial-injection seam rather than server-side timing, which a bare
  loopback TCP handshake completes too fast to reliably instrument
  against — duplicate-target dedup, multi-host/port scans, out-of-scope
  blocking). A benchmark (`BenchmarkScanner_Scan`) measures ports/sec
  against local fixtures only. `go test -race ./...` passes repository-wide.
  Integration tests (`test/integration/network_persistence_test.go`, real
  PostgreSQL): end-to-end persistence, re-scan `FirstSeen`/`LastSeen`
  dedup, unauthorized-target refusal, dry-run (nothing persisted), and the
  required multi-source test — HTTP and network discovery of the same
  host:port produce two distinct, non-contradictory asset rows (`PORT` vs
  `HTTP_ENDPOINT`), not a false merge or a contradictory duplicate.

### Fixed (proactively, learned from Phase 3)
- Network evidence excludes `scan_id` from the fingerprinted evidence data
  from the start — Phase 3 shipped this bug and fixed it after catching it
  in manual verification (see that phase's changelog entry); Phase 4
  applies the same fix immediately, confirmed by re-scanning a fixture
  port three times against a live database and observing the evidence
  count hold constant while `LastSeen` advanced.

## Phase 3 — HTTP Discovery Engine

### Added
- `internal/discovery/http`: the discovery engine — `Config`
  (`ResolvePaths` for named profiles), `ScopeValidator`, `GenerateCandidates`
  (deterministic, deduplicated, scope-checked), `Analyze` (evidence-based
  service classification), `ClassifyAICandidate` (deterministic weighted
  AI-candidate scoring — never a provider/model claim), and `Scanner`
  (bounded-concurrency execution over the Phase 1 HTTP client).
- `internal/discovery/model`: `Result`/`Summary`/`ServiceType`.
- `internal/discovery/service`: orchestrates authorization + scope setup,
  runs the scanner, and persists results through Phase 2's `AssetService`
  (`RecordObservation` + `UpsertEndpoint`) — no second identity or SQL
  layer.
- `internal/httpclient`: `Options.AllowRedirectTo` (per-hop redirect
  policy hook — nil preserves every existing caller's behavior) and
  `Response.RedirectChain`, extending rather than duplicating the Phase 1
  transport.
- `Config.Discovery.HTTP` (`internal/config`): enabled, timeout,
  concurrency, response-size/redirect limits, methods (GET-only,
  enforced), schemes, paths, AI-candidate detection toggle, and named
  profiles (`quick`, `comprehensive`) — all YAML/env configurable, no
  hard-coded path lists.
- `cmd/cli scan`: `ai-surface scan --target <target> [--target-type]
  [--profile] [--format table|json] [--timeout] [--concurrency]
  [--dry-run]`. `cmd/cli target authorize`: the (now load-bearing, not
  merely diagnostic) command to move a target to `AUTHORIZED`.
- `test/fixtures/http`: a fully local, offline HTTP fixture server (web
  page, JSON API doc, OpenAI-compatible-*shaped* AI API, health check,
  steerable redirect, oversized response, HTTP error) plus a standalone
  `cmd/fixtureserver` binary for manual testing.
- `docs/architecture/http-discovery.md`: full Phase 3 architecture
  writeup with a Mermaid diagram.
- Unit tests (`internal/discovery/http/*_test.go`): candidate generation,
  scope validation, response analysis, AI candidate detection/confidence,
  bounded concurrency, cancellation, failure isolation, and out-of-scope
  redirect blocking. Integration tests
  (`test/integration/discovery_persistence_test.go`, real PostgreSQL):
  end-to-end persistence, re-scan dedup (`FirstSeen`/`LastSeen`),
  response-change handling, unauthorized-target refusal, failed-endpoint
  isolation, and in-scope redirect following.

### Fixed
- A real bug found during this phase's own manual verification: evidence
  records included a per-scan `scan_id` inside the data that Phase 2's
  evidence deduplication fingerprints, so every re-scan of a byte-for-byte
  unchanged response created a brand-new evidence row forever. `scan_id`
  is now included in the asset/endpoint `Metadata` (where it's harmless —
  always reflects the most recent scan) but excluded from the evidence
  data that gets fingerprinted.

## Phase 2 — Asset Model & Persistence Engine

### Added
- `internal/domain/{validation,target,asset,endpoint}`: Target, Asset,
  AssetEvidence, and Endpoint entities — types, format validation
  (`Validate()`, no network I/O), deterministic asset identity
  (`asset.Identity`/`IdentityKey`), recursive secret redaction
  (`asset.SanitizeMetadata`), evidence fingerprinting
  (`asset.EvidenceFingerprint`), and URL normalization
  (`endpoint.Normalize`).
- `internal/repository/{pagination,sqlerr,target,asset,endpoint}`:
  cursor-based pagination shared by every `List`, pgx-error ->
  `internal/errors` translation, and PostgreSQL repositories for all four
  entities, including atomic `Upsert` (`INSERT ... ON CONFLICT DO UPDATE`)
  for assets and endpoints and deduplicating `CreateEvidence`.
- `internal/service/{target,asset}`: `TargetService` (validation,
  duplicate detection, the explicit authorization-status boundary) and
  `AssetService` (validation, identity, redaction,
  `RecordObservation` — a transactional upsert-asset-and-record-evidence
  operation).
- `database.Pool.WithTx`: single-transaction helper (extends the existing
  Phase 1 pool; no second connection pool).
- Migrations `000002`-`000005`: `targets`, `assets`, `asset_evidence`,
  `endpoints`, with CHECK constraints, foreign keys, and the unique
  indexes backing deduplication.
- `cmd/cli target` / `cmd/cli asset`: development diagnostics for the new
  persistence layer (not the future scan CLI).
- `docs/architecture/asset-model.md`: full Phase 2 architecture writeup
  with an ER diagram.
- `test/integration/{helpers,target_persistence,asset_persistence}_test.go`:
  real-PostgreSQL coverage of CRUD, upsert/deduplication, evidence
  persistence and immutability, endpoint normalization, a 50-goroutine
  concurrent-upsert test, pagination, filters, and transaction atomicity.

## Phase 1 — Core Platform Foundation

### Added
- `internal/httpclient`: safe-by-default HTTP transport abstraction
  (Client/Request/Response/Options), with configurable timeout, pooled
  connections, bounded response size, bounded redirects, TLS metadata
  capture, and SHA-256 body hashing.
- `internal/health`: standalone liveness/readiness checking package,
  extracted from `internal/httpserver`.
- `Config.Application` (name/environment/version) and `Config.Security`
  (`require_authorization`, `dry_run`) sections.
- Expanded `Config.Database` pool settings: `MaxOpenConnections`,
  `MaxIdleConnections`, `ConnMaxLifetime`, `ConnMaxIdleTime`.
- `Config.HTTPClient` section backing `internal/httpclient`.
- `cmd/cli config validate` (nested under a new `config` parent command)
  and `cmd/cli health` (standalone readiness check).
- `cmd/migrate version` (prints the current highest-applied migration
  version).
- `cmd/worker` now actively verifies PostgreSQL and Redis at startup and
  re-checks periodically as its (log-based) health mechanism.
- Top-level `migrations/` package (embedded `embed.FS`), replacing
  migrations co-located inside `internal/migrate`.
- `SECURITY.md`, `docs/architecture/foundation.md`.

### Changed
- **Breaking:** environment variable prefix renamed `AISURFACE_*` ->
  `AI_SURFACE_*` throughout (config, `.env.example`, docker-compose).
- **Breaking:** `Config.Redis` now uses a single `Address` (`host:port`)
  field instead of separate `Host`/`Port`; `DB` renamed `Database`.
- **Breaking:** `internal/apperror` renamed `internal/errors` (import
  alias: `apperrors`); gained `Configuration`, `Database`, `Network`,
  `HTTP`, `Authorization` categories and a `Wrap` alias for `New`.
- **Breaking:** `internal/store/postgres` renamed `internal/database`.
- **Breaking:** `internal/store/redisstore` renamed `internal/redis`.
- **Breaking:** `internal/app` renamed `internal/application`; gained an
  `HTTPClient` field.
- Migration filenames now use `NNNNNN_description.sql` (6-digit) instead
  of `NNNN_description.sql` (4-digit).
- `internal/httpserver` now delegates readiness aggregation to
  `internal/health` instead of implementing it inline.
- `ServerConfig` gained `ReadHeaderTimeout` and `IdleTimeout`; the HTTP
  server now sets all four `net/http.Server` timeouts explicitly.
- Makefile gained `test-unit`, `migrate`, `docker-up`/`docker-down` as
  aliases for existing targets, plus `migrate-version`.

## Phase 0 — Repository Bootstrap

### Added
- Go module, Makefile, structured JSON logging (`log/slog`), internal
  error model, build-time version info.
- `internal/config`: layered configuration (defaults -> YAML -> env vars
  -> CLI flags) with strict validation.
- `internal/store/postgres` (pgx pool) and `internal/store/redisstore`
  (go-redis client), each with a connect-and-ping `HealthCheck`.
- `internal/migrate`: dependency-free SQL migration runner
  (`go:embed`-based), with the initial `schema_migrations` bookkeeping
  migration.
- `internal/httpserver`: HTTP server with request-ID, structured-logging,
  and panic-recovery middleware, plus `/health` and `/ready`.
- `internal/app`: dependency-injection container wiring config, logger,
  database, Redis, and the HTTP server, with graceful shutdown on
  SIGINT/SIGTERM.
- `cmd/server`, `cmd/cli` (`version`, `validate`), `cmd/worker`
  (lifecycle skeleton), `cmd/migrate` (`up`, `status`).
- Docker development environment (Postgres + Redis + server via
  docker-compose), GitHub Actions CI, full unit + integration test suite.
