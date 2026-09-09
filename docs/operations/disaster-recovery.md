# Disaster Recovery

This platform's entire durable state lives in one place: **PostgreSQL**.
Redis is used only for health-checking today (no application data is
cached or queued there — confirmed by inspection of every phase's use of
`internal/redis`); losing it loses no data, only the worker's own
periodic health-check log line. Every recovery scenario below therefore
reduces to "recover PostgreSQL, then restart the application."

## Failure scenarios and recovery steps

### PostgreSQL is down

- **Symptom**: `/ready` reports the `database` dependency `unavailable`;
  every `cli`/`server` operation touching the database fails with a
  database-category error (`internal/errors.CategoryDatabase`).
- **Recovery**: restore PostgreSQL service (restart the instance, fail
  over to a replica, or restore from backup per the Backup Restoration
  section below). No application-level action is needed once PostgreSQL
  is reachable again — `internal/database.Pool` reconnects automatically
  on the next query (pgxpool manages its own connection lifecycle; there
  is no manual "reconnect" step in this codebase).

### PostgreSQL data is corrupted or lost

- **Recovery**: restore from the most recent verified backup (see Backup
  Restoration below), then re-run `go run ./cmd/migrate up` to confirm the
  restored schema is at the expected version, then re-run any scans/
  detections/correlations for the affected window if the loss window
  included unprocessed evidence.

### Redis is down

- **Symptom**: `/ready` reports the `redis` dependency `unavailable`;
  `cmd/worker`'s periodic health check logs `worker_health_check` with a
  degraded status.
- **Recovery**: restore the Redis service. No data recovery is needed —
  see this document's opening paragraph.
- **Impact while down**: `/ready` reports the whole application not-ready
  (by design — a load balancer should stop routing to an instance that
  can't reach a configured dependency), but the CLI-driven engines
  (detection/correlation/investigation/analytics/reporting) do not
  actually read from Redis at all today and continue to function when
  invoked directly — this is a known conservative-but-safe mismatch
  between `/ready`'s strictness and actual functional dependency,
  documented rather than silently "fixed" by loosening `/ready` (a
  false-positive-ready orchestrator signal is worse than an
  over-cautious one).

### Application secret/credential loss

- **Recovery**: rotate/reissue the lost credential in whatever secret
  store owns it (see `docs/security/production-hardening.md`'s Secrets
  section — this platform reads credentials only from environment
  variables, never from its own database or config files), update the
  environment, restart the affected process(es). No application data is
  encrypted with an application-managed key today (confirmed by
  inspection — there is no encryption-at-rest code in this codebase
  beyond whatever PostgreSQL/the underlying disk itself provides), so
  credential loss cannot make existing data unreadable.

### Application (server/worker) crash or unexpected restart

- **Recovery**: the process manager (systemd, Docker's own restart
  policy, an orchestrator) restarts the binary. `cmd/server`/`cmd/worker`
  perform no unflushed in-memory writes that would need recovery —
  every mutation goes directly to PostgreSQL inside a transaction
  (`internal/database.Pool.WithTx`); a crash mid-transaction rolls back
  cleanly, per PostgreSQL's own guarantees.

## Backup Restoration

`ai-surface-platform` ships no backup automation of its own — back up
PostgreSQL using your platform's standard tooling (`pg_dump`/
`pg_basebackup`, a managed database's own snapshot feature, WAL
archiving for point-in-time recovery, etc.). Recommended baseline:

- **Frequency**: nightly full logical backup (`pg_dump`) at minimum;
  continuous WAL archiving if point-in-time recovery matters for your
  use case.
- **Retention**: operator-defined based on how far back you need to
  recover from — this platform imposes no retention requirement on
  backups themselves (see Data Retention below for the platform's own
  data-retention behavior, which is a separate question from how long
  *backups* of that data are kept).
- **Encryption**: encrypt backups at rest and in transit to wherever
  they're stored — this platform's data model includes findings,
  intelligence records, and AI-context that can describe an assessed
  organization's real infrastructure; a leaked backup is a leaked
  security assessment.
- **Storage**: off-host, access-controlled, isolated from the
  application's own database credentials (see
  `docs/security/production-hardening.md`'s Backup Security section) —
  the account with permission to read backups should not be the same
  account the application uses to connect to PostgreSQL day-to-day.
- **Verification**: a backup that has never been restored is not a
  verified backup. See the Restore Test result below for what this phase
  actually verified in this environment.

## Restore Test

**Result**: not executed against a live PostgreSQL instance in this
development environment — no PostgreSQL server was reachable during this
phase's work (the standing sandbox limitation noted in every prior
phase's report). This is recorded honestly rather than claimed:
`docs/operations/production-readiness-report.md`'s Backup/Restore Results
section carries the same finding, flagged as an open item for the first
real deployment environment.

**What an operator should do to actually verify this**, in a non-production
environment:

```sh
# 1. Take a backup of a database with real (or realistic test) data
pg_dump -Fc "$AI_SURFACE_DATABASE_NAME" > backup.dump

# 2. Restore it into a fresh, separate database
createdb aisurface_restore_test
pg_restore -d aisurface_restore_test backup.dump

# 3. Point a throwaway config at the restored database and verify
AI_SURFACE_DATABASE_NAME=aisurface_restore_test \
  go run ./cmd/migrate status   # should show every migration already applied
AI_SURFACE_DATABASE_NAME=aisurface_restore_test \
  go run ./cmd/cli target list  # should show the restored data
```

Verify: the database restores without error, `cmd/migrate status` shows
the expected version with nothing pending, and a handful of read
operations (`target list`, `finding list --target ...`, etc.) return the
data you expect. Document the actual result (pass/fail, and any error
output) the first time this is run against a real deployment's backup —
do not carry this document's own "not executed" status forward once it
has been.

## Disaster recovery targets (RTO/RPO)

These are **operational targets an operator sets for their own
deployment**, not guarantees this codebase enforces — nothing in this
platform measures or alerts on RTO/RPO breach today (no
metrics/alerting infrastructure exists — see
`docs/operations/runbook.md`'s Observability section).

| Target | Suggested starting point | Depends on |
| --- | --- | --- |
| RTO (Recovery Time Objective) | Time to restore PostgreSQL from your chosen backup method + redeploy the application | Your backup method (logical dump vs. PITR vs. managed-service snapshot restore) and infrastructure automation |
| RPO (Recovery Point Objective) | Time since your last backup/WAL-archived point | Your backup frequency — nightly `pg_dump` implies up to 24h of potential loss; continuous WAL archiving implies near-zero |

Set these explicitly for your own deployment and revisit them once a
real restore test (see above) gives you an actual measured restore
duration.

## Application recovery

Redeploy the last known-good binaries/image (see
`docs/operations/deployment.md`'s Rollback section) and restart — the
application itself holds no state that needs separate recovery beyond
what's already covered by the database recovery steps above.

## Database recovery

Covered above (Backup Restoration).

## Secret recovery

Covered above (Application secret/credential loss).

## Verification after recovery

1. `/health`, `/live`, `/ready` all report OK.
2. `go run ./cmd/migrate status` shows no pending migrations.
3. A read-only smoke check (`ai-surface target list`,
   `ai-surface analytics overview --target <known target>`) returns
   expected data.
4. Check recent structured logs for unexpected errors following restart.
