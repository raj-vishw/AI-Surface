# Operations Runbook

Procedures for common operational situations. Written from what this
codebase actually does (confirmed by inspection this phase), not
speculation — see each section's source references.

## Known limitations (read this first)

- **No metrics/tracing library** (no Prometheus/OpenTelemetry dependency
  in `go.mod`) — signal comes from structured JSON logs
  (`internal/logging`) only. "High error rate" or "high latency" alerting
  (§94) must be built on your log aggregator's own query/alerting
  features against the `http_request` log line's `status`/`duration_ms`
  fields, not a scrape endpoint this platform exposes.
- **No job queue** — `cmd/worker` verifies dependencies on a timer and
  does nothing else yet (see its own `worker_has_no_job_queue_yet` log
  line). "Worker failure" below means the process died, not "a job
  failed," since no job execution exists yet.
- **No authentication** — every procedure below assumes the operator
  already has the OS/database access needed to run the CLI directly; there
  is no separate "who is allowed to run this command" check to
  troubleshoot.

## Service down

1. Check the process is actually running (`systemctl status`, `docker ps`,
   or your orchestrator's pod status).
2. Check `GET /health` (or `/live`) — if that also fails, the process is
   not accepting connections at all; check its logs for a crash/panic
   (`internal/httpserver`'s `recoveryMiddleware` catches panics from
   request handlers and logs `panic_recovered`, but a panic during
   startup, before the server begins listening, is not caught by it).
3. Restart the process. `cmd/server`'s graceful-shutdown path
   (`internal/application.Application.Run`) means a normal `SIGTERM`
   always finishes in-flight requests before exiting — an unclean exit
   (no `shutdown_signal_received`/`server_stopped_cleanly` log lines)
   indicates a crash, not a requested stop; check the log line
   immediately before the gap for the cause.

## Database failure

1. `GET /ready` will report `{"name":"database","status":"unavailable"}`.
2. Check PostgreSQL is reachable from the application host
   (`pg_isready -h <host> -p <port>`, matching the same check
   `deployments/docker/docker-compose/dev.yml`'s own healthcheck uses).
3. See `docs/operations/disaster-recovery.md`'s "PostgreSQL is down"
   section for recovery steps. No manual "reconnect" action is needed
   once PostgreSQL is reachable again — `internal/database.Pool` (pgxpool)
   reconnects on its own.
4. If PostgreSQL is up but connections are being refused/exhausted, check
   `database.max_open_connections` against PostgreSQL's own
   `max_connections` — this platform's pool never exceeds its configured
   `max_open_connections` (`internal/database`), so exhaustion means
   either that limit is set too high for PostgreSQL's own capacity, or
   another client is also consuming connections against the same
   instance.

## Queue failure (Redis)

1. `GET /ready` will report `{"name":"redis","status":"unavailable"}`.
2. See `docs/operations/disaster-recovery.md`'s "Redis is down" section —
   no application data is lost or at risk; Redis is currently used for
   health-checking only.
3. Restore Redis connectivity; `/ready` recovers automatically on its
   next check (`internal/health.CheckAll` runs fresh on every `/ready`
   request, not on a cached interval).

## Storage exhaustion

This platform stores no files on local disk beyond process logs (see Log
Rotation below) — reports/evidence live in PostgreSQL. "Storage
exhaustion" in practice means:

- **PostgreSQL disk full**: PostgreSQL itself will refuse writes; the
  application will surface database-category errors. Free space
  (`VACUUM`, archive/prune old data per your retention policy — see
  `docs/operations/disaster-recovery.md`'s Data Retention notes) or grow
  the volume.
- **Log disk full on the application host**: see Log Rotation below.

## High CPU / high memory

- No CPU/memory profiling endpoint is wired into this platform
  (`net/http/pprof` is not imported anywhere — confirmed by inspection).
  To investigate, attach a standard Go profiler manually
  (`go tool pprof` against a build with `net/http/pprof` imported
  temporarily), or use your platform's own container/host-level CPU/
  memory metrics to identify which process (server vs. worker vs. a
  long-running `cli` invocation) is responsible.
- The most likely source of high memory in a `cli` invocation specifically
  is an unbounded `--limit`/pagination parameter on a `list` command
  against a very large table — every list command is paginated
  (`internal/repository/pagination.MaxLimit` bounds the maximum page
  size), so this should not be unbounded in practice; if it is, that is a
  bug worth filing, not expected behavior.

## High latency

- Check `http_request` log lines' `duration_ms` field for which route is
  slow (there are only three: `/health`, `/live`, `/ready` — a slow
  `/ready` almost always means a slow PostgreSQL/Redis health check, not
  application logic).
- For a slow CLI command (e.g. a large `analytics`/`report` invocation),
  check `internal/analytics.Cache`'s effectiveness — repeated identical
  queries within its TTL (default 30s) are served from an in-process
  cache; a cold cache on a large target's first query of the day is
  expected to be the slowest case.
- Use PostgreSQL's own `EXPLAIN ANALYZE` against the specific query if a
  particular analytics/report type is consistently slow — see
  `docs/analytics/metrics.md` for which queries back which command.

## Authentication issues

Not applicable — this platform has no authentication layer (see
`docs/security/threat-model.md`'s trust-boundary section). "Authentication
issues" in the traditional sense do not exist; database connection
authentication failures show up as database-category errors at startup
(`connecting to database: ...`) and are resolved the same way any
PostgreSQL credential issue would be (verify `AI_RECON_DATABASE_USER`/
`AI_RECON_DATABASE_PASSWORD` against what PostgreSQL actually has
configured for that role).

## AI provider failure

- With `ai.enabled: false` (the shipped default in both
  `configs/defaults/config.yaml` and `configs/production/config.yaml`),
  this is not applicable — no AI request is ever made.
- With AI enabled: `internal/service/ai`'s provider-failure handling
  (Phase 13) already ensures a failed AI request never blocks or breaks
  detection/alerting/correlation/investigation/risk — those pipelines
  have no dependency on `internal/ai` at all (confirmed by inspection: no
  import of `internal/ai`/`internal/service/ai` exists anywhere under
  `internal/detection`, `internal/correlation`, `internal/investigation`,
  or `internal/intelligence`). A failing AI provider only affects
  `ai-recon ai ...` commands themselves, which surface the provider's
  error directly (see `docs/ai/safety.md`).

## Failed migration

1. `go run ./cmd/migrate status` shows which migration failed to apply.
2. Each migration file runs inside its own transaction
   (`internal/migrate`) — a failure rolls that migration back cleanly;
   the schema is left at the last successfully applied version, not
   partially migrated.
3. Fix the underlying cause (a conflicting manual schema change is the
   most common real-world cause for a migration tool failing partway
   through an otherwise-tested migration file) and re-run
   `go run ./cmd/migrate up`.

## Failed deployment

1. If the new binaries/image fail to start: check startup logs for a
   configuration validation error (`internal/config.Validate` fails fast
   and lists every problem found — see
   `docs/security/production-hardening.md`'s production guard rails,
   added this phase, for the most likely new failure mode after an
   upgrade to a production environment for the first time: `debug`
   logging, `require_authorization: false`, or `ssl_mode: disable` are
   now all startup-fatal when `AI_RECON_APP_ENV=production`).
2. Roll back per `docs/operations/deployment.md`'s Rollback section if the
   new version cannot be fixed forward quickly.

## Observability

- **Structured logs**: every process logs JSON via `log/slog`
  (`internal/logging`) — `level`, `msg`, plus operation-specific fields
  (`request_id`, `dependency`, `method`, `path`, `status`, `duration_ms`,
  etc.). Aggregate these with your platform's own log pipeline
  (CloudWatch Logs, Loki, ELK, etc.); nothing in this codebase writes
  logs anywhere but stdout.
- **Request IDs**: every HTTP request gets an `X-Request-ID` (generated,
  or echoed back if the caller supplied one) attached to every log line
  for that request (`internal/httpserver/middleware.go`'s
  `requestIDMiddleware`) — use it to correlate a client-visible failure
  with server-side log lines.
- **No correlation ID propagation into CLI-driven work** — a `cli`
  command run interactively has no request ID concept; use the
  timestamp and target/entity IDs already logged by each service to
  correlate instead.
