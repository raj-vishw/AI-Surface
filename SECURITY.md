# Security Model

This platform is intended for **authorized security testing, security
research, internal security assessments, CTFs, and labs** — it must only
be pointed at assets the operator has explicit permission to assess. See
`../doc_by_me/work.md` §2 for the full authorization-boundary
specification this project follows.

This document is the current, whole-project security summary as of
Phase 15 (the final planned development phase). For depth beyond this
summary, see:

- `docs/security/threat-model.md` — trust boundaries, threats, mitigations, residual risk
- `docs/security/production-hardening.md` — the concrete hardening checklist by area
- `docs/security/final-audit.md` — every finding from Phase 15's audit, with evidence and status
- `docs/security/final-security-checklist.md` — a flat pass/fail checklist
- `docs/security/risk-model-v1.md` — the risk-scoring model (Phase 10)
- `docs/compliance/evidence.md` — the generic, framework-agnostic control-evidence ledger (Phase 14)
- `docs/ai/safety.md` — AI-specific safety controls (Phase 13)

## What this platform is (and isn't)

`ai-recon-platform` is a **single-operator, CLI-driven** reconnaissance,
detection, correlation, investigation, and reporting toolkit. There is no
authentication, RBAC, or multi-tenancy anywhere in this codebase — this
is a deliberate, documented architectural choice for its actual use case
(one trusted operator with their own database/environment credentials),
not an oversight. See `docs/security/threat-model.md`'s trust-boundary
section for exactly what that does and doesn't protect against, and
`docs/security/final-audit.md`'s SEC-01 for the explicit residual-risk
statement covering it. Deploying this behind a public, multi-user,
unauthenticated network boundary is out of scope until a future phase
adds an authentication layer.

## Established controls (accumulated across Phases 1–15)

- **Authorization gate**: `security.require_authorization` /
  `security.dry_run` (`internal/config`,
  `AI_RECON_SECURITY_REQUIRE_AUTHORIZATION` /
  `AI_RECON_SECURITY_DRY_RUN`) — carried through configuration and
  validation; `AI_RECON_APP_ENV=production` additionally makes
  `require_authorization: false` a startup-fatal configuration error
  (Phase 15).
- **No secrets in source, logs, or version control.** Every
  credential-shaped configuration field is read only from environment
  variables (`.env`, gitignored — see `.env.example` for the safe
  template), never from YAML or the database.
  `config.DatabaseConfig.RedactedDSN()` masks the password wherever a
  connection string appears in logs. `internal/health`/`/ready` log the
  *real* dependency-check error server-side but return only a generic
  `"unreachable"` reason to callers. Phase 15 ran `gitleaks` against the
  full working tree and confirmed no real secret is committed (see
  `.gitleaks.toml`).
- **Safe-by-default HTTP client.** `internal/httpclient` enforces a
  request timeout, a bounded maximum response size, and a maximum
  redirect count on every request, restricted by hostname/subdomain
  scope (`internal/discovery/http.ScopeValidator`) — and, since Phase 15,
  additionally refuses to connect to any link-local or cloud-metadata
  address at the resolved-IP level (`internal/httpclient/ssrf.go`),
  immune to DNS rebinding. See `docs/security/threat-model.md`'s T2.
- **No arbitrary command execution.** No `os/exec` (or any shell
  invocation) exists anywhere in this codebase (confirmed by inspection,
  Phase 15) — there is no command-injection attack surface to exploit.
  The AI assistant (Phase 13) can only call a fixed, read-only tool
  allowlist; it never reaches a shell.
- **No SQL injection.** Every query is parameterized; every
  `fmt.Sprintf`-built query interpolates only compile-time-constant
  column names and placeholder indices, never a value (audited,
  Phase 15 — 21 call sites, all clean).
- **Configuration fails closed.** `internal/config.Validate()` never
  silently substitutes a default for an invalid value; Phase 15 added
  production-specific guard rails (rejecting `debug` logging, disabled
  authorization requirement, or disabled database TLS whenever
  `AI_RECON_APP_ENV=production`).
- **Dependency/secret/toolchain hygiene.** Phase 15 added `govulncheck`,
  `gitleaks`, and a container image scan to CI; bumped the Go toolchain
  to 1.26.6 to close 6 standard-library vulnerabilities found this
  phase.
- **Report/export security.** Reports are versioned and citation-
  validated against their own evidence (`internal/ai.ValidateCitations`,
  reused directly); exports redact secrets
  (`internal/ai.Redact`, reused directly) and escape CSV-injection
  characters (OWASP's mitigation); evidence packages carry a SHA-256
  integrity manifest, never used as an authentication mechanism. See
  `docs/reporting/reports.md`.

## Explicitly out of scope

- Authentication, RBAC, multi-tenancy (see "What this platform is"
  above — a future phase's work, not this one's).
- Stealth/evasion of any kind — `doc_by_me/work.md` permanently forbids
  it; only bounded, low-noise operation is supported (concurrency/rate
  limits throughout `internal/config`).
- Blocking outbound requests to RFC1918/loopback addresses — an
  authorized internal-network penetration test is a supported use case;
  only link-local/cloud-metadata ranges are unconditionally blocked (see
  above).
- A general-purpose prompt-injection classifier for the AI assistant —
  mitigated structurally (typed facts, not raw target text; a read-only
  tool allowlist; citation validation), not by a separate ML classifier.

## Reporting a vulnerability in this project

This is a personal, single-maintainer project without a public release.
If you find a security issue in the platform's own code (as opposed to a
finding produced *by* using the platform against an authorized target),
report it to the project maintainer directly rather than opening a public
issue. No dedicated security-contact email is configured for this project
at this time (phase15.md §115 — this is not invented here; it is the
project owner's decision to make).
