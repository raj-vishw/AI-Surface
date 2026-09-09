# Production Readiness

This document defines what "production" means for `ai-surface-platform` as
it exists today, and what an operator must provide to run it that way. It
does not claim capabilities this codebase doesn't have — see
`docs/security/final-audit.md` and `docs/operations/production-readiness-report.md`
for the honest, evidence-based verdict on how ready this actually is.

## What kind of "production" this platform supports

`ai-surface-platform` is a **single-operator, CLI-driven security
reconnaissance and assessment tool**, not a multi-tenant SaaS. There is no
authentication, RBAC, or multi-user session layer anywhere in this
codebase (confirmed by inspection across every phase since Phase 1 —
see `docs/security/threat-model.md`'s trust-boundary section). "Production"
here means: **a trusted operator, with their own OS-level and
database-level credentials, running this platform against targets they
are authorized to assess, on infrastructure they control** — the same
operating model as nmap, Metasploit, or Burp Suite, not a hosted web
application serving untrusted end users. Deploying this behind a public,
unauthenticated network boundary is explicitly out of scope until a
future phase adds an authentication/authorization layer (see
docs/security/threat-model.md's residual-risk section).

## Supported environments

| Component | Requirement |
| --- | --- |
| Go toolchain | 1.26.6+ (see go.mod; `GOTOOLCHAIN=auto` will fetch it) |
| PostgreSQL | 16+ (developed/migrated against `postgres:16-alpine`) |
| Redis | 7+ (developed against `redis:7-alpine`) — currently used only for future job-queue infrastructure and health-checking; no application data is cached there yet |
| OS/architecture | Linux/amd64 primary target (Dockerfile.server uses `distroless/static-debian12`); the Go toolchain and this codebase have no OS-specific code, so darwin/amd64 and linux/arm64 are expected to work but are not part of this project's CI matrix |

## Required infrastructure

- One PostgreSQL instance reachable from the server/worker/CLI/migrate
  processes. This platform issues no cross-database or cross-schema
  queries; a single database is sufficient.
- One Redis instance (currently used for health-checking only — see
  `docs/operations/runbook.md`'s "Known Limitations" — the platform's
  actual detection/correlation/analytics data all lives in PostgreSQL).
- Outbound network access from wherever discovery/detection/intelligence
  commands run, to whatever targets are being assessed (and, if AI is
  enabled, to the configured AI provider's endpoint).
- No message queue, object storage, or CDN is required — reports/evidence
  packages are stored as rows in PostgreSQL (see
  `docs/reporting/reports.md`), not as files.

## Minimum resources

This platform has not been load-tested at any specific scale in this
environment (no live PostgreSQL/Redis instance was reachable during this
phase's work — see `docs/operations/production-readiness-report.md`'s
Performance section for exactly what was and wasn't measured). As a
starting point for a single-operator deployment:

- 1 vCPU / 1 GiB RAM is sufficient to run `cmd/server` and `cmd/worker`
  idle (both are small, dependency-light Go binaries with no in-process
  caching beyond `internal/analytics.Cache`'s small bounded map).
- PostgreSQL sizing depends entirely on how much target/event/finding
  history is retained — see `docs/operations/disaster-recovery.md`'s data
  retention notes. Every list endpoint in this platform is paginated
  (`internal/repository/pagination`), so query cost does not grow
  unboundedly with table size the way an unpaginated query would.

## Dependencies

See `go.mod` for the full pinned dependency list. Phase 15 ran
`govulncheck ./...` against it (see
`docs/operations/production-readiness-report.md`'s Verification Results)
and found zero vulnerabilities affecting this module's own dependencies —
the vulnerabilities found and fixed this phase were all in the Go
standard library itself, resolved by bumping the toolchain to 1.26.6 (see
`CHANGELOG.md`'s Phase 15 entry).

## Configuration

Configuration is layered (`internal/config.Load`, precedence low to high):

1. Hard-coded Go defaults (`internal/config.defaultConfig`)
2. `configs/defaults/config.yaml`
3. `configs/<AI_SURFACE_APP_ENV>/config.yaml` (`configs/development/config.yaml`
   or the new `configs/production/config.yaml` — see
   `docs/security/production-hardening.md`)
4. `AI_SURFACE_*` environment variables

`AI_SURFACE_APP_ENV=production` now additionally activates startup guard
rails in `Config.Validate()` (added this phase): logging.level may not be
`debug`, `security.require_authorization` may not be `false`, and
`database.ssl_mode` may not be `disable` — an invalid combination refuses
to start rather than run with an unintended production setting
(phase15.md §3/§107).

## Secrets

Never committed. See `.env.example` for the full list of variable names
this platform reads, with safe placeholder values and descriptions — copy
it to `.env` (gitignored) for local use, or set the same variables through
your deployment platform's own secret store (Kubernetes Secret, AWS
Secrets Manager + env injection, systemd `EnvironmentFile`, etc.). See
`docs/security/production-hardening.md`'s Secrets section for the full
audit of every credential-shaped configuration field in this codebase.

## Database

- Run `ai-surface-platform`'s `migrate` binary (`make migrate-up` / `go run
  ./cmd/migrate up`) before starting `server`/`worker`/`cli` against a new
  database. 14 migrations exist today (`migrations/000001_initial.sql`
  through `migrations/000014_create_reporting.sql`).
- `database.ssl_mode` defaults to `disable` in `configs/defaults/config.yaml`
  (a local-Postgres convenience) and is overridden to `require` in the new
  `configs/production/config.yaml` — see
  `docs/security/production-hardening.md`.
- Connection pool bounds (`database.max_open_connections` /
  `max_idle_connections` / `connection_max_lifetime` /
  `connection_max_idle_time`) are all configurable — see
  `docs/operations/deployment.md`'s Database section for sizing guidance.

## Storage

No object storage is used. Reports, evidence-package manifests, and
control evidence are rows in PostgreSQL (`reports`, `evidence_packages`,
`evidence_items`, `control_evidence` — see
`migrations/000014_create_reporting.sql`) — back up the database and you
have backed up every report/evidence artifact this platform has ever
produced. See `docs/compliance/evidence.md` for what an evidence item
actually stores (a hash and a reference, never a copy of the underlying
data).

## Networking

- `cmd/server` listens on `server.host`/`server.port`
  (`0.0.0.0:8080` by default) and exposes only `/health`, `/live`, and
  `/ready` (see `internal/httpserver`) — there is no REST API surface
  beyond these three endpoints in this codebase (confirmed by
  inspection); every actual security-platform operation (scanning,
  detection, correlation, investigation, reporting, etc.) is invoked via
  the `cli` binary, not over HTTP.
- Do not expose PostgreSQL or Redis ports publicly — see
  `docs/architecture/overview.md`'s security-boundary diagram for the
  recommended network segmentation.
- TLS termination is expected to happen in front of `cmd/server` (a
  reverse proxy/load balancer) — this platform's own HTTP server does not
  terminate TLS itself. See `docs/operations/deployment.md`.

## Observability

Every process (`server`, `worker`, `cli`, `migrate`) logs structured JSON
via `log/slog` (`internal/logging`) with a request ID attached to every
HTTP request (`internal/httpserver`'s `requestIDMiddleware`). There is no
metrics/tracing library wired in (confirmed by inspection — no
Prometheus/OpenTelemetry dependency exists in `go.mod`); see
`docs/operations/runbook.md`'s Observability section for what log-based
signal is actually available today and how to alert on it.

## Backups

See `docs/operations/disaster-recovery.md` for the documented backup/
restore procedure. **A backup that has never been restored is not a
backup** (phase15.md §21) — this phase's restore test result (executed or
not, and why) is recorded honestly in
`docs/operations/production-readiness-report.md`'s Backup/Restore
Results section; do not treat this document's existence as proof backups
work until that section says a restore was actually verified.

## Recovery

See `docs/operations/disaster-recovery.md` for failure-scenario-by-
failure-scenario recovery steps, and `docs/operations/runbook.md` for the
operational playbook to follow when something is actually down.

## Upgrade procedure

1. Read `CHANGELOG.md`'s entry for the target version.
2. Back up the database (see `docs/operations/disaster-recovery.md`).
3. Stop `server`/`worker`.
4. Deploy the new binaries/image.
5. Run `go run ./cmd/migrate up` (idempotent — already-applied migrations
   are skipped; see `internal/migrate`).
6. Start `server`/`worker`.
7. Verify `/health`, `/live`, `/ready` all report OK, and run a smoke
   workflow (`ai-surface target list`, or the full workflow in
   `docs/operations/runbook.md`).

## Rollback procedure

See `docs/operations/deployment.md`'s Rollback section — in short:
redeploy the previous binaries/image (this platform's migrations are
additive-only so far — no migration has ever dropped a column or table;
see `docs/operations/disaster-recovery.md`'s migration-rollback notes for
what "rollback" can and cannot mean for a schema that has already
accepted writes under the new version).
