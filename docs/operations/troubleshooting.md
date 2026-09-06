# Troubleshooting

Real errors and behaviors this platform actually produces, found by
reading its own error-construction code and by running its verification
suite in this development environment — not invented scenarios
(phase15.md §122).

## "loading configuration: invalid configuration: ..."

`internal/config.Validate()` fails fast and lists every problem it found
in one message, e.g.:

```
fatal: loading configuration: invalid configuration:
  - server.port must be between 1 and 65535, got 99999
  - logging.level "verbose" must be one of debug, info, warn, error
```

As of this phase, running with `AI_RECON_APP_ENV=production` adds three
possible new entries here that were previously accepted in every
environment:

```
  - logging.level must not be "debug" when application.environment is "production" (phase15.md §33)
  - security.require_authorization must be true when application.environment is "production" (see SECURITY.md)
  - database.ssl_mode must not be "disable" when application.environment is "production" (see docs/operations/production-readiness.md)
```

**Fix**: correct the named field(s). This is deliberate fail-fast
behavior (phase15.md §107), not a bug — see
`docs/security/production-hardening.md`.

## "connecting to database: ..." at startup

The database is unreachable or credentials are wrong. Verify
`AI_RECON_DATABASE_HOST`/`PORT`/`USER`/`PASSWORD`/`NAME` against a running
PostgreSQL instance; `internal/config.DatabaseConfig.RedactedDSN()`
appears in logs with the password masked, so the logged connection string
is safe to share when asking for help, but never share the raw
`AI_RECON_DATABASE_PASSWORD` value itself.

## `/ready` returns 503 with `"reason":"unreachable"`

This is intentional and documented behavior, not a bug to "fix" by
changing the response: `internal/health.CheckAll` deliberately never
returns the real underlying error to an API caller (it could contain
internal connection details) — the real error is logged server-side
under `readiness_check_failed`. Check your own server-side logs for the
actual cause; see `docs/operations/runbook.md`'s Database/Queue failure
sections.

## `httpclient: refusing to connect to link-local/metadata address ...`

New this phase (`internal/httpclient/ssrf.go`). Every outbound request
this platform makes — discovery, detection, intelligence lookups — now
refuses to connect to `169.254.0.0/16` (IPv4 link-local, where every
major cloud provider serves its instance-metadata endpoint) or
`fd00:ec2::254` (AWS IMDSv2's IPv6 address), regardless of the hostname
or redirect chain that led there. This is not a bug: no legitimate
authorized recon target is a link-local address, and a target that
resolves or redirects to one is exactly the SSRF pattern this guard
exists to stop (see `docs/security/threat-model.md`). Loopback and
RFC1918/private addresses are **not** blocked by this guard — an
authorized internal-network target continues to work exactly as before.

## `gofmt`/`go vet`/`golangci-lint`/`govulncheck`/`gitleaks` failures in CI

- `gofmt -l .` non-empty output: run `make fmt` to fix in place.
- `go vet` / `golangci-lint`: fix the reported issue; this project's
  `.golangci.yml` enables `gosec` — a `//nolint:errcheck` comment alone
  does not silence a `gosec` finding on an ignored `Flush()`/`Close()`
  error; use `_ = expr` instead (see `cmd/cli/commands/reports.go`'s
  `printReport` for the established pattern).
- `govulncheck ./...` reporting a standard-library vulnerability: check
  whether a newer Go toolchain fixes it (`go.mod`'s `go` directive pins
  the version; `GOTOOLCHAIN=auto`, the Go default, fetches a newer patch
  release automatically once `go.mod` names it — see this phase's own
  `go 1.26.5` → `go 1.26.6` bump in `CHANGELOG.md`, which resolved 6 real
  stdlib vulnerabilities this way).
- `gitleaks` reporting a finding inside a test fixture that is
  deliberately secret-shaped (e.g. `internal/ai/redaction_test.go`): add
  the file to `.gitleaks.toml`'s `[allowlist].paths` with a comment
  explaining why, rather than changing the test fixture itself — the
  fixture needs to look like a real secret to prove the redaction engine
  actually catches it.

## `make lint` / `golangci-lint` not found locally

Not committed to this repository (it's a development tool, not a
dependency) — install it per
https://golangci-lint.run/welcome/install/, or
`go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`
(the version this phase actually verified against: v2.13.2).

## A report/analytics command returns stale-looking numbers

`internal/analytics.Cache` caches aggregate results for
`analytics.DefaultCacheTTL` (30 seconds), keyed by target + metric + time
range + filters (`internal/analytics/cache.go`) — a number that looks
stale for up to 30 seconds after new data lands is expected, not a bug.
Wait for the TTL to expire, or reduce `DefaultCacheTTL` in code if your
use case needs fresher aggregates than that (there is no runtime flag to
override it today — see `docs/analytics/dashboards.md`'s Caching
section).

## A CSV export cell starts with an unexpected leading `'`

Intentional — `internal/reporting.EscapeCSVValue` prefixes any cell
beginning with `=`, `+`, `-`, `@`, a tab, or a carriage return with a
leading single quote (OWASP's spreadsheet-formula-injection mitigation —
see `docs/reporting/reports.md`'s Export section). Opening the CSV in a
spreadsheet application will display the value with that leading quote
stripped visually in most applications; the raw file legitimately
contains it.

## Docker build fails on `COPY configs ./configs`

The image build context must be the repository root (see
`deployments/docker/docker-compose/dev.yml`'s `context: ../../..`) — run
`docker build -f deployments/docker/Dockerfile.server .` from the
repository root, not from `deployments/docker/`.

## `make dev-up` fails with "POSTGRES_PASSWORD must be set"

Copy `.env.example` to `.env` first (`cp .env.example .env`) and adjust
`POSTGRES_PASSWORD` — `deployments/docker/docker-compose/dev.yml`
deliberately has no fallback default for the database password (its
`${POSTGRES_PASSWORD:?...}` syntax fails the compose run with that exact
message rather than silently starting with an empty password).
