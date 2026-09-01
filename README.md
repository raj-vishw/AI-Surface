# AI Reconnaissance Platform

A platform for discovering, fingerprinting, and performing authorized
security assessments of AI/LLM systems. See `../doc_by_me/` for the full
project specification, architecture, and phased roadmap.

**Status: Phase 3 — HTTP discovery engine.** Phase 1's platform foundation
plus Phase 2's asset/evidence/endpoint persistence layer, now with the
platform's first real reconnaissance capability: `ai-recon scan` discovers
HTTP/HTTPS services and endpoints against an authorized target, classifies
them (including AI/LLM API *candidate* detection — never a specific
provider/model claim), and persists everything through the Phase 2
persistence layer. Fingerprinting, vulnerability probing, DNS/port/
subdomain discovery, distributed workers, the dashboard, authentication,
and RBAC are not implemented yet.

## 1. Prerequisites

- Go 1.26+
- Docker and Docker Compose (for local Postgres/Redis/server)

## 2. Setup

```sh
git clone <this repo>
cd ai-recon-platform
go mod tidy
cp .env.example .env   # then edit values as needed
```

## 3. Environment configuration

Configuration is layered, lowest to highest priority:

1. built-in defaults (`internal/config`)
2. `configs/defaults/config.yaml`
3. `configs/<environment>/config.yaml` (environment from `AI_RECON_APP_ENV`, default `development`)
4. `AI_RECON_*` environment variables
5. CLI flags, where a command supports them (`--config-dir`, `--env`, `--log-level`)

See `.env.example` for the full list of recognized environment variables
(server, database, redis, HTTP client, logging, security). Secrets
(database/redis passwords) are never read from YAML — only from
environment variables / `.env`.

## 4. Starting PostgreSQL and Redis

```sh
make dev-up      # (alias: make docker-up) starts PostgreSQL, Redis, and the API server via Docker Compose
make dev-ps      # check container health
make dev-down    # (alias: make docker-down) stop and remove everything
```

To run Postgres/Redis via Docker but the server/worker/CLI directly on the
host instead:

```sh
make dev-up
export $(grep -v '^#' .env | grep -v '^$' | xargs)
```

## 5. Running migrations

```sh
go run ./cmd/migrate up        # or: make migrate / make migrate-up
go run ./cmd/migrate status    # or: make migrate-status
go run ./cmd/migrate version   # or: make migrate-version
```

Migration files live in the top-level `migrations/` directory
(`000001_initial.sql`, ...), embedded into the binary at build time.

## 6. Starting the server

```sh
make run-server       # or: go run ./cmd/server
```

The worker and CLI are runnable the same way:

```sh
make run-worker        # or: go run ./cmd/worker
go run ./cmd/cli version
go run ./cmd/cli config validate
go run ./cmd/cli health
```

## 7. Checking health

```sh
curl http://localhost:8080/health   # liveness: is the process running
curl http://localhost:8080/ready    # readiness: are Postgres/Redis reachable (503 if not)
go run ./cmd/cli health             # same readiness check, standalone (no server needed)
```

## 8. Running tests

```sh
make test              # unit tests (alias: make test-unit)
make test-integration  # requires `make dev-up` first — exercises real Postgres/Redis
make vet
make fmt-check          # gofmt -l, fails on unformatted files (used in CI)
make lint               # golangci-lint
make build-all          # build every executable into bin/
```

## Asset Persistence

The platform maintains a normalized, deduplicated asset inventory backed
by PostgreSQL (`internal/domain`, `internal/repository`,
`internal/service`; full writeup in
[docs/architecture/asset-model.md](docs/architecture/asset-model.md)):

- **Target** — the authorized scope being assessed (a domain, host, IP,
  CIDR, URL, repository, or cloud account). A target's mere existence is
  never authorization to act against it — `authorization_status` starts
  `UNVERIFIED` and only becomes `AUTHORIZED` through an explicit call.
- **Asset** — anything discovered within a target's scope (a host, IP,
  port, HTTP/API/AI endpoint, repository, cloud resource, ...), with a
  deterministic **identity** computed from its type-appropriate fields
  (hostname, IP, host+port+protocol, or normalized URL — never a display
  name or response content). The same identity is always the same row.
- **Deduplication** — two discovery sources observing the same real-world
  asset collapse into one row via `INSERT ... ON CONFLICT DO UPDATE`,
  race-free under concurrent writers.
- **Evidence** — the append-only observation history backing each asset
  (a DNS answer, an HTTP response, a TLS certificate, ...); never mutated,
  deduplicated by a fingerprint of its (redacted) data.
- **Historical tracking** — `first_seen` is fixed at an asset's original
  discovery and never overwritten; `last_seen` advances with every
  observation; lifecycle `status` changes only through an explicit call,
  never as a side effect of being re-observed (or not observed).

Every metadata field — asset, evidence, and endpoint alike — passes
through a redaction boundary before it is ever logged or stored: keys
matching common secret patterns (`password`, `token`, `authorization`,
`cookie`, `api_key`, ...) are replaced with `"[REDACTED]"`.

Run the database integration tests (requires `make dev-up` first):

```sh
make test-integration
```

They exercise real PostgreSQL directly — no mocking — covering migrations,
CRUD, upsert/deduplication, evidence persistence, endpoint URL
normalization, concurrent upserts (50 goroutines against the same
identity), pagination, filters, and transaction atomicity.

## HTTP Discovery

`ai-recon scan` discovers HTTP/HTTPS services and endpoints against an
already-created, already-**authorized** target, classifies each response
(including AI/LLM API *candidate* detection, never a specific provider or
model — see
[docs/architecture/http-discovery.md](docs/architecture/http-discovery.md)),
and persists everything through the Asset Persistence layer above. Full
walkthrough:

```sh
# 1. Create a target and authorize it — scan refuses an unauthorized target.
ai-recon target create --name "local test" --type URL --value http://127.0.0.1:9000
ai-recon target authorize --id <uuid-printed-above>

# 2. Start a local test target (no real Internet target required):
go run ./test/fixtures/http/cmd/fixtureserver -port 9000

# 3. Scan it.
ai-recon scan --target http://127.0.0.1:9000 --profile quick
```

- **Authorization requirement** — `scan` loads the target, validates it,
  and checks `authorization_status == AUTHORIZED` before generating a
  single candidate URL or sending a single request; an unauthorized
  target fails immediately with "target is not authorized for active
  discovery".
- **`--profile quick`** — a small, high-value path set (`/`,
  `/robots.txt`, `/openapi.json`, `/v1/models`, `/health` by default).
- **`--profile comprehensive`** — the full configured path set
  (`discovery.http.paths`). Both profiles, and any custom ones, are
  defined in configuration (`discovery.http.profiles`), never hard-coded.
- **`--dry-run`** (or `security.dry_run: true`) — prints the candidate
  `METHOD path` list without sending any request or persisting anything.
- **`--format json`** — machine-readable output on stdout; operational
  logs always go to stderr, so stdout is always valid JSON in this mode.
- **Troubleshooting**: "target is not authorized for active discovery"
  means run `ai-recon target authorize --id <uuid>` first; "target type ...
  is not supported by HTTP discovery" means the target's type isn't
  `URL`/`HOST`/`DOMAIN`; an empty result table with all rows `ERROR`
  usually means the target isn't reachable — confirm the fixture/target is
  actually running and the port matches.

## Executables

| Command       | Purpose                                                     |
| ------------- | ------------------------------------------------------------ |
| `cmd/server`  | HTTP API server (`/health`, `/ready`)                        |
| `cmd/cli`     | `ai-recon` CLI (`version`, `config validate`, `health`, `target`, `asset`, `scan`) |
| `cmd/worker`  | Background worker: verifies Postgres/Redis, graceful shutdown |
| `cmd/migrate` | Database migration runner (`up`, `status`, `version`)         |

`ai-recon asset` (and `target create`/`target list`) remain development
diagnostics for exercising the Phase 2 persistence layer by hand (see
their `--help`); `ai-recon target authorize` and `ai-recon scan` are real,
required parts of running Phase 3 discovery.

## Further reading

- [SECURITY.md](SECURITY.md) — authorization boundary, safe defaults
- [docs/architecture/asset-model.md](docs/architecture/asset-model.md) —
  Phase 2 asset model, identity/deduplication, persistence architecture
- [docs/architecture/http-discovery.md](docs/architecture/http-discovery.md) —
  Phase 3 HTTP discovery engine: scope, concurrency, AI candidate
  detection, redirect handling