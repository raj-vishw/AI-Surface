# Phase 1 Architecture: Core Platform Foundation

This document describes the foundation built in Phase 1 — the packages
every later phase (discovery, fingerprinting, probing, orchestration,
dashboard) builds on. It does not describe those later subsystems, which
don't exist yet.

## Package map

```text
internal/
├── config/       configuration schema + layered loader
├── logging/      structured JSON logger, request-scoped via context
├── errors/       internal error model (import alias: apperrors)
├── httpclient/   safe-by-default HTTP transport abstraction
├── database/     PostgreSQL connection pool
├── redis/        Redis client
├── health/       liveness/readiness checking
├── httpserver/   HTTP server, routing, middleware, /health + /ready
├── application/  dependency-injection container / bootstrap
└── version/      build-time version info

migrations/       embedded SQL migration files (top-level, see below)
```

## Configuration architecture

`internal/config.Config` is a strongly-typed tree: `Application`, `Server`,
`Database`, `Redis`, `HTTPClient`, `Logging`, `Security`. `config.Load()`
builds it by layering, in increasing priority:

1. hard-coded defaults (`defaultConfig()`)
2. `configs/defaults/config.yaml`
3. `configs/<environment>/config.yaml`
4. `AI_SURFACE_*` environment variables

A fifth, optional layer — CLI flags — is applied by callers via
`ApplyOverrides` (see `cmd/cli/commands/config.go`) after `Load()` returns,
since only some executables (the CLI) expose flag overrides.

`Config.Validate()` is called at the end of `Load()` and rejects any
invalid value outright (bad ports, non-positive timeouts, unrecognized log
level/environment/SSL mode, `max_idle_connections > max_open_connections`,
a `redis.address` that isn't `host:port`, ...). It never silently
substitutes a default for an invalid value — a misconfigured process
refuses to start rather than run with an unintended setting.

## Logging architecture

`internal/logging` wraps `log/slog` (no external dependency). `New(Options)`
builds a `*slog.Logger` in JSON or text format at a configurable level.
`WithContext`/`FromContext` attach a request-scoped logger to a
`context.Context` — `internal/httpserver`'s request-ID middleware attaches
one per request (see below), so every log line for that request carries
its `request_id` automatically without every call site having to thread
one through explicitly.

## Error architecture

`internal/errors` (imported as `apperrors` to avoid colliding with the
standard library's `errors`) defines `Error{Cause, Category, Message,
HTTPStatus}`. Categories: `validation`, `configuration`, `database`,
`network`, `http`, `authorization`, `not_found`, `unauthorized`,
`forbidden`, `conflict`, `unavailable`, `timeout`, `internal` — each maps
to a default HTTP status. `ClientMessage()` returns a safe, non-leaking
message for `internal`/`database`/`configuration` categories (driver
errors and internal configuration detail must never reach API clients);
everything else exposes its `Message` as-is. `errors.Is`/`errors.As` work
through `Unwrap()` to the original cause for logging/debugging.

## HTTP client architecture

`internal/httpclient` is a reusable transport — **not** the discovery
engine — that future discovery/fingerprinting subsystems build on. A
`Client` (built via `New(Options)` or `NewFromConfig(cfg.HTTPClient)`)
wraps `*http.Client` with:

- a configurable request timeout
- pooled connections (`MaxIdleConnections`, `MaxConnectionsPerHost`)
- a maximum response size, enforced via `io.LimitReader` — a response body
  is never read unbounded into memory
- a maximum redirect count: once reached, the client stops following
  further redirects and returns the last response as-is
  (`http.ErrUseLastResponse`) rather than erroring
- TLS metadata capture (negotiated version, cipher suite, peer certificate
  count) and a SHA-256 body hash on every `Response`, for later
  fingerprinting use

It intentionally does **not** restrict which hosts a redirect may point to
— host-allowlisting (SSRF protection) is deferred to the phase that uses
this client against real, potentially-adversarial targets.

## Database architecture

`internal/database.Connect(ctx, cfg)` builds a `pgxpool.Pool`, sized from
`config.DatabaseConfig`'s four pool knobs (`MaxOpenConnections` ->
`MaxConns`, `MaxIdleConnections` -> `MinConns`, `ConnMaxLifetime` ->
`MaxConnLifetime`, `ConnMaxIdleTime` -> `MaxConnIdleTime` — pgxpool has no
separate "idle" cap distinct from `MinConns`, so that's the closest
equivalent), and never returns a `Pool` that hasn't been confirmed
reachable with a ping. `Pool.HealthCheck(ctx)` re-pings for readiness
checks. No application repositories exist yet — this is infrastructure
only, until a real schema is introduced.

## Redis architecture

`internal/redis.Connect(ctx, cfg)` mirrors the database package: builds a
`go-redis` client from `cfg.Redis.Address` (a single `host:port`, not
separate host/port fields), pings before returning, and exposes
`HealthCheck`. For Phase 1 this is infrastructure only — no job queue,
scheduling, distributed locks, or rate limiting yet.

## Bootstrap sequence

`internal/application.New(ctx, cfg, logger)` is the DI container for
`cmd/server`:

```text
LoadConfig (cmd/server, before New)
    ↓
InitializeLogger (cmd/server, before New)
    ↓
InitializeDatabase   (database.Connect)
    ↓
InitializeRedis      (redis.Connect)
    ↓
InitializeHTTPClient (httpclient.NewFromConfig)
    ↓
InitializeHealth     (health.Dependency{...} wired into httpserver.New)
    ↓
InitializeServer     (httpserver.New)
```

If any step fails, resources already connected are closed before the error
is returned — callers never receive a partially-initialized `Application`
they'd need to clean up themselves. `cmd/worker` follows the same
Database/Redis verification steps directly (it has no HTTP server to wire
health into).

## Graceful shutdown

Every executable installs `signal.NotifyContext(ctx, os.Interrupt,
syscall.SIGTERM)` and shuts down in this order:

```text
stop accepting new connections (http.Server.Shutdown)
        ↓
wait for in-flight requests to finish, bounded by server.shutdown_timeout
        ↓
close Redis
        ↓
close PostgreSQL
        ↓
exit
```

`httpserver.Server.ListenAndServe()` returns `nil` (not
`http.ErrServerClosed`) on a clean shutdown, so `application.Run` can
distinguish "shut down as requested" from "server crashed."

## Health/readiness

`internal/health.CheckAll(ctx, logger, dependencies)` runs every
`Dependency`'s `HealthCheck` and aggregates a `Report{Status, Checks}`.
Failures are logged (with the real error) server-side but the `Report`
itself only ever carries the generic reason `"unreachable"` — see the
error architecture section above. `internal/httpserver` renders this as
`GET /health` (liveness — is the process alive, no dependency checks) and
`GET /ready` (readiness — 200 if every dependency is reachable, 503
otherwise). `cmd/cli health` runs the same check standalone, without a
running server.

## Local development

See the top-level [README.md](../../README.md) for the full step-by-step
setup (prerequisites, `.env`, `make dev-up`, migrations, running the
server, health checks, tests). In short: `cp .env.example .env`, `make
dev-up`, `go run ./cmd/migrate up`, `make run-server`, `curl
localhost:8080/ready`.
