# Production Hardening

This is the concrete, evidence-based hardening checklist for
`ai-recon-platform` as it exists after Phase 15. Where a section says
"not applicable," that reflects an actual architectural fact confirmed by
inspection this phase, not an unaddressed gap — see
`docs/security/threat-model.md` for the reasoning and
`docs/security/final-audit.md` for anything genuinely open.

## Authentication

None exists (confirmed by inspection across every phase since Phase 1 —
no session/token/password-handling code anywhere in this codebase). This
platform's trust boundary is **whoever can run the CLI has the database
credentials configured in their own environment** — the same model as
nmap or Metasploit, not a hosted service. See
`docs/security/threat-model.md`'s trust-boundary section for what this
does and does not protect against, and for what a future phase adding
network-exposed multi-user access would need to add first.

## Authorization

No RBAC exists. The one authorization boundary this platform enforces is
**target scoping**: `internal/service/ai`, `internal/service/detection`,
and `internal/service/reporting` all check that a resolved entity's own
`TargetID` matches the caller's requested target, rejecting a mismatch
with `apperrors.NewForbidden` (HTTP-equivalent 403) — see
`internal/service/reporting/sections.go` and this phase's new
`internal/service/reporting/isolation_test.go` for a test proving this
boundary. Direct "get by ID" operations elsewhere in the codebase
(`asset.GetByID`, `investigation.GetByID`, etc.) are unscoped primary-key
lookups — this is consistent with the no-multi-tenancy model above, not
an inconsistency: an operator with CLI access already has unrestricted
access to every target in their own database.

## TLS

`cmd/server`'s HTTP server does not terminate TLS itself (confirmed by
inspection — no certificate-loading code exists in `internal/httpserver`).
Terminate TLS at a reverse proxy in front of it; see
`docs/operations/deployment.md`. Database connections: `database.ssl_mode`
now defaults to `require` in the new `configs/production/config.yaml`
(previously `disable` in every environment, inherited from
`configs/defaults/config.yaml`, which remains the local-development
default) — see `internal/config`'s new production-only startup guard rail
rejecting `ssl_mode: disable` when `AI_RECON_APP_ENV=production`.

## Secrets

Every credential-shaped configuration field (`database.password`,
`redis.password`, `ai.provider.api_key_env`,
`intelligence.threat_feed.api_key_env`) is read only from environment
variables, never from a YAML file or the database (confirmed by
inspection of `internal/config`) — see `.env.example` for the full list.
`config.DatabaseConfig.RedactedDSN()` masks the password anywhere a
connection string might be logged. `internal/ai.Redact` scrubs
secret-shaped strings (API keys, AWS access keys, bearer tokens, private
key blocks, cookies) from AI context/output and report content before
either is persisted or exported (`internal/reporting.RedactSections`
reuses it directly — see `docs/reporting/reports.md`). This phase ran
`gitleaks detect` against the working tree (see .gitleaks.toml) and found
zero real secrets — the five findings it initially reported were all this
platform's own redaction-engine test fixtures (deliberately
secret-shaped strings used to prove `internal/ai.Redact` and
`internal/discovery/dns.SanitizeTXTValue` work), now allowlisted by path
with the reasoning documented inline in `.gitleaks.toml`.

## Network

- Outbound requests (discovery/detection/intelligence) now refuse to
  connect to link-local/cloud-metadata addresses
  (`internal/httpclient/ssrf.go`, added this phase — see
  `docs/security/threat-model.md`'s SSRF entry) regardless of hostname or
  redirect chain, closing the one concrete SSRF gap this phase's audit
  found: `internal/discovery/http.ScopeValidator` restricted requests by
  *hostname* (same-host-or-subdomain) but never checked the *resolved
  IP*, so a target whose DNS pointed at a cloud metadata address would
  previously have been queried.
- Do not expose PostgreSQL (5432) or Redis (6379) ports publicly — see
  `docs/architecture/overview.md`'s security-boundary diagram.
- No CORS header is ever set (`internal/httpserver`) — this server has no
  browser-facing frontend and no cookie-based session for a cross-origin
  request to exploit, so the correct posture is "cross-origin access is
  simply never granted," not a permissive `Access-Control-Allow-Origin:
  *` that then needs restricting.
- No CSP is meaningful for a browser-facing page because there is no such
  page; `internal/httpserver`'s three JSON endpoints now send
  `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
  anyway (added this phase — see `internal/httpserver/middleware.go`'s
  `securityHeadersMiddleware`), which is the correct policy for an API
  that never serves HTML.

## Database

- Migrations (`internal/migrate`, `migrations/*.sql`) never `CREATE
  ROLE`/`GRANT` — provisioning a least-privilege application database
  user is the operator's responsibility (see
  `docs/operations/deployment.md`'s Database section). Recommended
  grants: `CONNECT` on the database, `SELECT, INSERT, UPDATE, DELETE` on
  every application table, nothing on `pg_catalog`/superuser-only
  functions, and no `CREATE`/`DROP` privilege at all — this platform's
  own runtime code issues no DDL outside `cmd/migrate`, so the
  application user does not need schema-modification rights (confirmed
  by inspection: no `CREATE TABLE`/`ALTER TABLE` string appears anywhere
  outside `migrations/*.sql` and `internal/migrate`).
- Every query built with `fmt.Sprintf` in this codebase (audited this
  phase — 21 call sites across `internal/repository/*`) interpolates only
  compile-time-constant column-name lists and a `$N` placeholder *index*,
  never a value; every actual value is passed as a pgx query parameter.
  No SQL string concatenation of user-controlled data exists anywhere in
  this codebase (confirmed by inspection this phase).
- Connection pool bounds (`database.max_open_connections`,
  `max_idle_connections`, `connection_max_lifetime`,
  `connection_max_idle_time`) are all configurable — see
  `configs/defaults/config.yaml` for current defaults (20/10/30m/5m).

## Logging

Production defaults to `logging.level: info` (`configs/production/
config.yaml`, and now enforced — `debug` is startup-fatal when
`AI_RECON_APP_ENV=production`). No secret is ever logged (confirmed by
inspection: every place a credential could reach a log call goes through
`RedactedDSN()` or is simply never logged — e.g. `AI_RECON_DATABASE_PASSWORD`
is read once into `Config.Database.Password` and never passed to a
logger call anywhere in this codebase).

## AI

See `docs/ai/safety.md` for Phase 13's own hardening (prompt-injection
defenses, tool allowlist, read-only tools, citation validation, secret
redaction). Unchanged this phase: `ai.enabled: false` remains the shipped
default in every environment, and no core security pipeline
(detection/correlation/investigation/risk/alerting) imports
`internal/ai`/`internal/service/ai` at all (confirmed by inspection this
phase) — an AI provider outage cannot break any of them.

## Exports

`internal/reporting`'s CSV export escapes spreadsheet-formula-injection
characters (`EscapeCSVValue`) and JSON export relies on
`encoding/json`'s default HTML-escaping — both already covered by
dedicated tests (`internal/reporting/csv_test.go`,
`internal/reporting/json_test.go`) and re-verified this phase (see
`docs/security/final-security-checklist.md`).

## Backups

See `docs/operations/disaster-recovery.md`'s Backup Security notes:
encrypt backups at rest/in transit, store them access-controlled and
isolated from the application's own database credentials.
