# AI Reconnaissance Platform

A platform for discovering, fingerprinting, and performing authorized
security assessments of AI/LLM systems. See `../doc_by_me/` for the full
project specification, architecture, and phased roadmap.

**Status: Phase 1 — core platform foundation.** Configuration, structured
logging with request correlation IDs, an internal error model, a
safe-by-default HTTP client abstraction (`internal/httpclient`), PostgreSQL
and Redis connectivity, migrations, liveness/readiness checks, and the
`server` / `cli` / `worker` / `migrate` executables. Discovery,
fingerprinting, vulnerability probing, distributed workers, the dashboard,
authentication, and RBAC are not implemented yet.

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

## Executables

| Command       | Purpose                                                     |
| ------------- | ------------------------------------------------------------ |
| `cmd/server`  | HTTP API server (`/health`, `/ready`)                        |
| `cmd/cli`     | `ai-recon` CLI (`version`, `config validate`, `health`)       |
| `cmd/worker`  | Background worker: verifies Postgres/Redis, graceful shutdown |
| `cmd/migrate` | Database migration runner (`up`, `status`, `version`)         |

## Further reading

- [SECURITY.md](SECURITY.md) — authorization boundary, safe defaults
- [docs/architecture/foundation.md](docs/architecture/foundation.md) — Phase 1 architecture
- [CHANGELOG.md](CHANGELOG.md)
