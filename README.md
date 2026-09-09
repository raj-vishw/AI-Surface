# AI Surface Platform

A CLI-driven platform for discovering, fingerprinting, and performing
authorized security assessments of AI/LLM systems and general
infrastructure — recon scans, passive fingerprinting, finding detection,
correlation, threat intelligence, risk scoring, an optional AI
investigation assistant, and reporting, all built on one normalized,
evidence-backed data model.

There is no server component and no web UI — everything is a subcommand
of the `ai-surface` CLI, run directly against PostgreSQL/Redis.

## Features

- **Discovery** — HTTP, TCP (network), and DNS/subdomain scanning against
  an explicitly authorized target only
- **Passive fingerprinting** — technology/framework/AI-provider
  identification from already-collected evidence, no extra requests
- **Endpoint & API discovery** — bounded crawling, OpenAPI/Swagger/
  GraphQL detection; an inventory engine, never a vulnerability scanner
- **Finding detection** — passive by default, evidence-backed, with
  severity and confidence tracked separately
- **Investigation & correlation** — case management, explainable
  cross-signal correlation, attack-chain classification
- **Threat intelligence & risk scoring** — local enrichment by default,
  external providers opt-in only
- **Detection rule engine & alerting** — versioned, deterministic rules
  over this platform's own normalized data
- **AI investigation assistant** — evidence-grounded, citation-validated,
  disabled by default, works entirely offline with a mock provider
- **Analytics, reporting & evidence packages** — dashboards, versioned
  reports, exportable evidence manifests, generic compliance-evidence
  ledger

## Requirements

- Go 1.26+
- PostgreSQL 16+
- Redis 7+

## Installation

```sh
git clone <this repo>
cd ai-surface-platform
go build -o bin/ai-surface ./cmd/cli
```

Or run any command directly with `go run ./cmd/cli <command>` during
development.

## Configuration

Configuration is layered, lowest to highest priority: built-in defaults →
`configs/defaults/config.yaml` → `configs/<environment>/config.yaml`
(environment from `AI_SURFACE_APP_ENV`, default `development`) →
`AI_SURFACE_*` environment variables → CLI flags, where a command
supports them (`--config-dir`, `--env`, `--log-level`).

```sh
cp .env.example .env   # then edit values as needed
```

See `.env.example` for the full list of recognized environment variables.
Secrets (database/Redis passwords, API keys) are never read from YAML —
only from environment variables/`.env`.

## Quick start

```sh
# 1. Start PostgreSQL and Redis (any local install or your own containers),
#    then point .env at them and apply migrations.
go run ./cmd/migrate up

# 2. Create a target and authorize it — every scan refuses an
#    unauthorized target.
go run ./cmd/cli target create --type DOMAIN --value example.com --name "example"
go run ./cmd/cli target authorize --id <uuid-printed-above> --status AUTHORIZED

# 3. Discover, fingerprint, and detect.
go run ./cmd/cli scan --target example.com
go run ./cmd/cli fingerprint --target example.com
go run ./cmd/cli findings scan --target example.com
go run ./cmd/cli findings list --target example.com
```

## Commands

| Command | Purpose |
| --- | --- |
| `target` | Create, authorize, and list targets — the authorization boundary every scan enforces |
| `asset` | [dev diagnostic] Inspect the persisted asset inventory directly |
| `scan` | HTTP discovery against an authorized target |
| `network-scan` | TCP connect discovery against an authorized target |
| `dns-scan` / `subdomain-scan` | DNS record discovery and subdomain enumeration |
| `fingerprint` | Passive technology identification from already-collected evidence |
| `endpoint-scan` | Application endpoint & API surface discovery |
| `findings` | Detect, list, and manage evidence-backed security findings |
| `investigate` | Analyst case management and finding correlation |
| `intel` | Threat intelligence lookup and enrichment |
| `risk` | Risk scoring for assets, findings, and investigations |
| `detection` / `alert` | Define, test, and evaluate detection rules; manage the alerts they produce |
| `correlation` / `chain` | Cross-signal correlation and attack-chain analysis |
| `ai` | AI-assisted investigation copilot — advisory only, disabled by default |
| `analytics` | Aggregate metrics and dashboard-equivalent views |
| `report` | Generate, review, approve, and export security reports |
| `evidence-package` | Export a report's cited evidence as a hashed manifest |
| `control` | Record generic control evidence — not a compliance certification |
| `health` | Check connectivity to PostgreSQL/Redis |
| `config` | Inspect and validate the effective configuration |
| `version` | Print version information |

Every command has its own `--help`; most support `--dry-run` (report what
would happen without making a request or persisting anything) and
`--format json` for scripting.

## Testing

```sh
make test              # unit tests
make test-race          # unit tests under the race detector
make test-integration   # requires a running PostgreSQL/Redis
make vet
make fmt-check
make lint               # golangci-lint
make security-check     # govulncheck + gitleaks
make build-all          # build every executable into bin/
```

## Documentation

Full architecture, security, and operations documentation lives under
[`docs/`](docs/), organized by area:

- **Architecture** — [`docs/architecture/`](docs/architecture/): system
  overview, and one design doc per subsystem (asset model, each discovery
  engine, fingerprinting, finding detection, investigation/correlation
  engines, threat intelligence, detection engine, AI assistant)
- **Detection** — [`docs/detection/`](docs/detection/): rule authoring,
  built-in rules, correlation strategies
- **Investigation** — [`docs/investigation/`](docs/investigation/):
  attack-chain model
- **AI** — [`docs/ai/`](docs/ai/): safety/trust boundaries, investigation
  guide
- **Analytics & reporting** — [`docs/analytics/`](docs/analytics/),
  [`docs/reporting/`](docs/reporting/),
  [`docs/compliance/`](docs/compliance/)
- **Security** — [`docs/security/`](docs/security/): threat model,
  hardening checklist, risk-scoring model, audit findings
- **Operations** — [`docs/operations/`](docs/operations/): deployment,
  production readiness, disaster recovery, runbook, troubleshooting, a
  from-scratch VM testing walkthrough

See also [SECURITY.md](SECURITY.md) for the authorization boundary and
safe defaults, and [CONTRIBUTING.md](CONTRIBUTING.md) for development
setup and contribution requirements.

## License

No license file exists in this repository yet — this is an explicit,
undecided choice left to the project owner, not an oversight. Do not
assume any particular license applies until one is added.
