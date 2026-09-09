# Deployment

## Prerequisites

- PostgreSQL 16+ and Redis 7+ reachable from wherever `worker`/`cli`/
  `migrate` run.
- A copy of `.env` (see `.env.example`) or equivalent environment
  variables / secret-manager injection providing at minimum
  `AI_SURFACE_DATABASE_PASSWORD` and, if Redis auth is enabled,
  `AI_SURFACE_REDIS_PASSWORD`.
- `AI_SURFACE_APP_ENV=production` for a production deployment — this
  activates `configs/production/config.yaml` and the production-only
  startup guard rails in `Config.Validate()` (see
  `docs/security/production-hardening.md`).

## Configuration

See `docs/operations/production-readiness.md`'s Configuration section for
the four-layer precedence. In practice, a production deployment sets:

```
AI_SURFACE_APP_ENV=production
AI_SURFACE_DATABASE_HOST=<your postgres host>
AI_SURFACE_DATABASE_PASSWORD=<from secret manager>
AI_SURFACE_DATABASE_SSL_MODE=require   # or verify-ca / verify-full
AI_SURFACE_REDIS_ADDRESS=<your redis host>:6379
AI_SURFACE_REDIS_PASSWORD=<from secret manager, if set>
```

Every other setting has a safe default via `configs/defaults/config.yaml`
+ `configs/production/config.yaml`.

## Database

1. Provision PostgreSQL 16+.
2. Create a dedicated database and a least-privilege application user
   (see `docs/security/production-hardening.md`'s Database section for
   the specific grants this platform actually needs — it never runs DDL
   at runtime outside `cmd/migrate`, so the application user does not
   need schema-modification privileges).
3. Point `AI_SURFACE_DATABASE_*` at it.

## Migrations

```
go run ./cmd/migrate status   # see what's pending
go run ./cmd/migrate up       # apply everything pending
go run ./cmd/migrate version  # print the current version
```

Migrations are ordered, numbered (`migrations/000001_initial.sql` …
`migrations/000014_create_reporting.sql`), and — as of Phase 15's audit —
contain no `DROP TABLE`/`DROP COLUMN` anywhere in this platform's history;
every phase has only added tables/columns/indexes. `cmd/migrate` tracks
applied versions in its own table (see `internal/migrate`) so re-running
`up` against an already-current database is a no-op, not an error.

## Startup

```
go run ./cmd/worker     # or the built `bin/worker` binary
```

`cmd/worker` logs `starting_worker`, verifies PostgreSQL and Redis, then
logs `worker_ready` — see `docs/operations/runbook.md`'s Known
Limitations for what the worker does and does not do today (it has no
job queue to consume yet). There is no server process — this platform is
CLI-only; `cmd/cli` runs directly wherever an operator has shell access
and needs no startup/listener of its own.

## Workers

`cmd/worker` has no job queue to consume yet (a standing, documented
limitation since Phase 1 — see its own `worker_has_no_job_queue_yet` log
line) — it currently only verifies PostgreSQL/Redis connectivity on a
30-second interval and demonstrates graceful shutdown. Running it is
optional today; it exists so the deployment shape (a separate worker
process) is already in place for the phase that adds real job
processing.

## Upgrades

See `docs/operations/production-readiness.md`'s Upgrade procedure. In
short: back up, stop, deploy, migrate, start, verify.

## Rollback

Redeploy the previous version's binaries/image and restart. Because every
migration to date is additive-only (no dropped table/column), an older
binary version running against a newer (migrated-forward) schema will
simply not read the newest columns/tables — it does not break on unknown
extra columns. Rolling the **schema** itself backward is not supported by
`cmd/migrate` (no `down` migrations are defined — see
`docs/operations/disaster-recovery.md`'s migration-rollback notes); if a
new migration must be undone, restore from the pre-migration backup
instead of attempting a manual reverse migration.
