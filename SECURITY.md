# Security Model

This platform is intended for **authorized security testing, security
research, internal security assessments, CTFs, and labs** — it must only
be pointed at assets the operator has explicit permission to assess. See
`../doc_by_me/work.md` §2 for the full authorization-boundary
specification this project follows.

Phase 1 establishes the foundation the authorization boundary is built on;
later phases (target allowlisting, scan-scope enforcement, active-probe
consent) build directly on top of it.

## What Phase 1 establishes

- **`security.require_authorization` / `security.dry_run` configuration**
  (`internal/config`, `AI_RECON_SECURITY_REQUIRE_AUTHORIZATION` /
  `AI_RECON_SECURITY_DRY_RUN`). These are carried through configuration and
  validation now; the discovery/probing subsystems that read and enforce
  them are introduced in later phases. Nothing in this codebase performs
  scanning or probing yet, so there is nothing to gate.
- **No secrets in source or logs.** Database/Redis passwords are never
  read from YAML — only from environment variables (`.env`, gitignored).
  `config.DatabaseConfig.RedactedDSN()` masks the password wherever a
  connection string needs to appear in logs or CLI output;
  `internal/health` and the `/ready` endpoint log the *real* error from a
  failed dependency check server-side but return only a generic
  `"unreachable"` reason to API/CLI callers — see `internal/errors`'
  `ClientMessage()`, which hides internal/database/configuration-category
  error detail from anything that isn't the operator's own logs.
- **Safe-by-default HTTP client.** `internal/httpclient` enforces a
  request timeout, a bounded maximum response size (bodies are never read
  unbounded into memory), and a maximum redirect count on every request.
  It does not yet restrict *which* hosts a redirect may point to —
  SSRF protection is explicitly deferred to the phase that introduces
  active target probing, per the master specification. Nothing in this
  phase issues requests to attacker- or user-supplied URLs.
- **No arbitrary command execution.** Nothing in this codebase executes
  shell commands, and no LLM/agent layer exists yet — when it is added
  (a later phase), the master specification requires every AI-generated
  action to pass a deterministic policy layer before reaching a scanner;
  `LLM → shell → target` is explicitly forbidden.
- **Configuration fails closed.** `internal/config.Validate()` never
  silently substitutes a default for an invalid value — an invalid
  configuration refuses to start rather than run with an unintended
  setting.

## What is explicitly out of scope for this phase

- Target authorization/allowlist enforcement (no scanning exists to gate).
- Rate limiting, stealth/evasion (deferred; work.md also permanently
  forbids evasion of security controls, only "low-noise operation").
- Authentication, RBAC, multi-tenancy, audit logging.
- SSRF host-allowlisting in `internal/httpclient` (the abstraction is
  prepared for it; enforcement lands with the phase that uses it against
  real targets).

## Reporting a vulnerability in this project

This is an internal-development-stage project without a public release.
If you find a security issue in the platform's own code (as opposed to a
finding produced *by* using the platform against an authorized target),
report it to the project maintainer directly rather than opening a public
issue.
