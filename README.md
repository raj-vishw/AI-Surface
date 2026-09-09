# AI Reconnaissance Platform

A platform for discovering, fingerprinting, and performing authorized
security assessments of AI/LLM systems. See `../doc_by_me/` for the full
project specification, architecture, and phased roadmap.

**Status: Phase 15 — production hardening (final planned phase).**
Phases 1–14 (platform foundation; asset/evidence/endpoint persistence;
HTTP/network/DNS/endpoint discovery; passive fingerprinting;
finding/vulnerability detection; investigation & incident correlation;
threat intelligence & risk; detection rule engine & alerting; advanced
correlation & attack chains; the AI investigation assistant; and
analytics/reporting/evidence/compliance) are all implemented, tested, and
documented — see `CHANGELOG.md` for the full per-phase history. Phase 15
audited and hardened the whole platform (SSRF protection, dependency/
secret/toolchain vulnerabilities, production configuration guard rails,
CI security scanning, security response headers) without adding new
product functionality — see `docs/security/final-audit.md` for every
finding and `docs/operations/production-readiness-report.md` for the
resulting verdict. There is still no frontend, job queue, or
authentication/RBAC layer — this remains a single-operator, CLI-driven
tool by design; see `docs/security/threat-model.md`.

## 1. Prerequisites

- Go 1.26+
- Docker and Docker Compose (for local Postgres/Redis/server)

## 2. Setup

```sh
git clone <this repo>
cd ai-surface-platform
go mod tidy
cp .env.example .env   # then edit values as needed
```

## 3. Environment configuration

Configuration is layered, lowest to highest priority:

1. built-in defaults (`internal/config`)
2. `configs/defaults/config.yaml`
3. `configs/<environment>/config.yaml` (environment from `AI_SURFACE_APP_ENV`, default `development`)
4. `AI_SURFACE_*` environment variables
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
curl http://localhost:8080/live     # same liveness check (alias — see phase15.md §25)
curl http://localhost:8080/ready    # readiness: are Postgres/Redis reachable (503 if not)
go run ./cmd/cli health             # same readiness check, standalone (no server needed)
```

## 8. Running tests

```sh
make test              # unit tests (alias: make test-unit)
make test-race          # unit tests under the race detector (required before merging concurrent code)
make test-integration   # requires `make dev-up` first — exercises real Postgres/Redis
make vet
make fmt-check          # gofmt -l, fails on unformatted files (used in CI)
make lint               # golangci-lint
make security-check     # govulncheck + gitleaks — see docs/security/production-hardening.md
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

`ai-surface scan` discovers HTTP/HTTPS services and endpoints against an
already-created, already-**authorized** target, classifies each response
(including AI/LLM API *candidate* detection, never a specific provider or
model — see
[docs/architecture/http-discovery.md](docs/architecture/http-discovery.md)),
and persists everything through the Asset Persistence layer above. Full
walkthrough:

```sh
# 1. Create a target and authorize it — scan refuses an unauthorized target.
ai-surface target create --name "local test" --type URL --value http://127.0.0.1:9000
ai-surface target authorize --id <uuid-printed-above>

# 2. Start a local test target (no real Internet target required):
go run ./test/fixtures/http/cmd/fixtureserver -port 9000

# 3. Scan it.
ai-surface scan --target http://127.0.0.1:9000 --profile quick
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
  means run `ai-surface target authorize --id <uuid>` first; "target type ...
  is not supported by HTTP discovery" means the target's type isn't
  `URL`/`HOST`/`DOMAIN`; an empty result table with all rows `ERROR`
  usually means the target isn't reachable — confirm the fixture/target is
  actually running and the port matches.

## Network Discovery

`ai-surface network-scan` performs authorized TCP connect discovery against a
`HOST`/`IP`/`CIDR` target, conservatively classifies open ports, and
persists them as `PORT` assets through the same persistence layer HTTP
discovery uses — see
[docs/architecture/network-discovery.md](docs/architecture/network-discovery.md)
for the full architecture, including why a reachable port is never treated
as proof of anything beyond "TCP reachable". **Scanning requires
authorization**, exactly like `ai-surface scan`: the target must already
exist and have `authorization_status = AUTHORIZED`
(`ai-surface target authorize --id <uuid>`) before `network-scan` will run
against it.

```sh
# Local test environment: HTTP services on :8000/:8080, a generic TCP
# service on :9000 — no external targets needed.
go run ./test/fixtures/localenv

ai-surface target create --name "local test" --type IP --value 127.0.0.1
ai-surface target authorize --id <uuid-printed-above>

# Single port
ai-surface network-scan --target 127.0.0.1 --ports 9000

# Port list
ai-surface network-scan --target 127.0.0.1 --ports 8000,8080,9000

# Port range
ai-surface network-scan --target 127.0.0.1 --ports 8000-8010

# Profiles (quick / standard / comprehensive — see configs/defaults/config.yaml)
ai-surface network-scan --target 127.0.0.1 --profile quick
ai-surface network-scan --target 127.0.0.1 --profile standard
ai-surface network-scan --target 127.0.0.1 --profile comprehensive

# Dry run — reports host:port pairs without connecting or persisting anything
ai-surface network-scan --target 127.0.0.1 --ports 8000-8010 --dry-run

# Machine-readable output (stdout is always valid, log-free JSON)
ai-surface network-scan --target 127.0.0.1 --ports 8000,8080 --format json
```

A `CIDR` target (e.g. `192.168.1.0/30`) expands to its usable host
addresses (network/broadcast excluded for ordinary subnets), bounded by
`discovery.network.max_hosts` (default 256) — exceeding the limit is
rejected outright, never silently truncated.

## DNS & Subdomain Discovery

`ai-surface dns-scan` performs authorized DNS record discovery (A, AAAA,
CNAME, MX, NS, TXT, SOA, CAA, plus reverse PTR) against a `DOMAIN`/`HOST`
target; `ai-surface subdomain-scan` is the same engine with wordlist-based
subdomain enumeration always on — see
[docs/architecture/dns-discovery.md](docs/architecture/dns-discovery.md)
for the full architecture, including wildcard DNS detection and why a
resolved name is never itself treated as proof an HTTP service is
listening there. **Scanning requires authorization**, exactly like
`ai-surface scan`/`network-scan`: the target must already exist and have
`authorization_status = AUTHORIZED` before `dns-scan`/`subdomain-scan`
will run against it.

```sh
# Local, fully offline DNS test fixture — no public DNS required.
go run ./test/fixtures/dns/cmd/dnsserver -port 5300

ai-surface target create --name "local test" --type DOMAIN --value example.test
ai-surface target authorize --id <uuid-printed-above>

# Record discovery only, against the local fixture.
ai-surface dns-scan --target example.test --resolvers 127.0.0.1:5300

# Subdomain enumeration with a wordlist.
ai-surface subdomain-scan --target example.test --resolvers 127.0.0.1:5300 --wordlist words.txt

# Profiles (quick / standard / comprehensive — see configs/defaults/config.yaml)
ai-surface dns-scan --target example.test --resolvers 127.0.0.1:5300 --profile quick

# Dry run — reports record types / candidate names without querying or persisting anything
ai-surface dns-scan --target example.test --profile comprehensive --dry-run

# Machine-readable output (stdout is always valid, log-free JSON)
ai-surface dns-scan --target example.test --resolvers 127.0.0.1:5300 --format json
```

Subdomain candidate generation is capped by
`discovery.dns.subdomains.max_candidates` (default 10,000) and
`max_depth` (default 1, higher only via an explicit `--max-depth` flag or
a profile that opts in) — both hard ceilings, never exceeded, never a
random sample when the ceiling is reached. Wildcard DNS is detected
before subdomain results are counted: a candidate indistinguishable from
the domain's wildcard baseline is excluded from
`Subdomains discovered`, while a distinct record under the same wildcard
domain is still recognized as genuine.

## Passive Fingerprinting

`ai-surface fingerprint` identifies technologies (web servers, frameworks,
frontends, CDNs, cloud providers, AI API candidates, database candidates,
...) from evidence Phase 3/4/5 already collected and persisted — see
[docs/architecture/fingerprinting.md](docs/architecture/fingerprinting.md)
for the full architecture. **It never performs a network or DNS request
of its own**: running it against an asset that was never actually
scanned produces no fingerprints, not an error. Every result names the
concrete signals (header values, DNS records, discovered paths, ...) that
produced it and is a candidate backed by a transparent, evidence-based
confidence score — never an opaque classification, and never a claim of
having actively verified anything.

```sh
# Analyze every asset discovered for a target so far.
ai-surface fingerprint --target example.com

# Analyze one specific asset.
ai-surface fingerprint --asset <asset-uuid>

# Show the supporting evidence behind each result.
ai-surface fingerprint --target example.com --explain

# Filter by category / minimum confidence.
ai-surface fingerprint --target example.com --category web_server --min-confidence 0.60

# Evaluate without persisting anything.
ai-surface fingerprint --target example.com --dry-run

# Machine-readable output (stdout is always valid, log-free JSON)
ai-surface fingerprint --target example.com --format json
```

Signatures are declarative YAML
(`internal/fingerprint/signatures/*.yaml`), not hard-coded Go — an
operator can point `fingerprint.signatures_path` at a custom directory to
extend or replace the built-in set. Re-running fingerprinting against
unchanged evidence is idempotent (no duplicate rows); a fingerprint that
stops matching is preserved as `INACTIVE`, never deleted, and every
add/remove/version-change/significant-confidence-change is reported as a
`Change` relative to the previous analysis.

## Endpoint & API Discovery

`ai-surface endpoint-scan` discovers application-level endpoints and API
surface from an authorized target — bounded crawling, HTML link/form
extraction, JavaScript static route extraction, robots.txt/sitemap.xml
parsing, and OpenAPI/Swagger discovery — see
[docs/architecture/endpoint-discovery.md](docs/architecture/endpoint-discovery.md)
for the full architecture. **It is an inventory engine, not a
vulnerability scanner**: it records `/api/users?id=123` as an endpoint
observation, it never tests `id=123'` or any other attack payload; it
only ever sends GET requests and never submits a discovered form.

```sh
# Crawl the target's own known HTTP(S) assets.
ai-surface endpoint-scan --target example.com --profile quick

# Comprehensive crawl with a machine-readable summary.
ai-surface endpoint-scan --target example.com --profile comprehensive --format json

# Explicit seed URL(s), bounded depth.
ai-surface endpoint-scan --target https://example.com --seed https://example.com/app --depth 2

# Report the crawl plan without making any request.
ai-surface endpoint-scan --target example.com --dry-run
```

Every discovered endpoint records **documented** (named in an OpenAPI/
Swagger spec), **observed** (an actual HTTP response was received), and
**inferred** (a weak signal only, e.g. a bare JavaScript string) as
independent, non-exclusive facts — a documented `DELETE
/api/users/{id}` the crawl never independently reached stays `observed =
false`, never silently upgraded. Crawl limits (`--depth`, `--max-pages`,
`--max-endpoints`, response size, concurrency, request rate) are all
enforced and configurable; an out-of-scope link is scope-rejected and
never requested, the same boundary every other discovery command in this
project enforces.

## Finding & Vulnerability Detection

`ai-surface findings scan` transforms evidence Phase 3/4/6/7 already
collected into structured, evidence-backed security findings — see
[docs/architecture/finding-detection.md](docs/architecture/finding-detection.md)
for the full architecture. **It defaults to passive analysis**: reading
already-persisted response headers, cookie attributes, TLS metadata,
endpoint classification, and technology fingerprints, with zero network
requests of its own. An optional `--mode safe_active` additionally allows
a small, bounded set of requests — only against an already-known endpoint
or one of a fixed handful of well-known paths (`/.git/HEAD`, `/.env`,
`/.well-known/security.txt`) — and requires the target be `AUTHORIZED`.

```sh
# Passive analysis (default) — no network request of its own.
ai-surface findings scan --target example.com

# Safe-active mode: a small set of additional bounded, already-known-path requests.
ai-surface findings scan --target example.com --mode safe_active

# Report the detection plan (enabled detectors, 0 network requests) without persisting anything.
ai-surface findings scan --target example.com --dry-run

# List / filter persisted findings.
ai-surface findings list --target example.com --severity high --format json
ai-surface findings list --target example.com --format csv

# One finding's full detail, evidence, and lifecycle history.
ai-surface findings show <finding-id>

# What changed during one specific scan.
ai-surface findings diff --target example.com --scan <scan-id>
```

Every finding separates **severity** ("how serious could this be") from
**confidence** ("how sure are we it's actually present") and never claims
exploitability — a missing header means exactly that, not "the
application is exploitable." A finding is never deleted: its lifecycle
moves `open -> resolved -> reopened` (or into a sticky, human-controlled
`accepted_risk`/`false_positive`), and every transition is recorded as an
immutable audit event. No detector performs exploitation, credential
attacks, brute-forcing, or evasion — see the architecture doc's "Not
Implemented" section for the complete boundary.

## Investigation & Incident Correlation

`ai-surface investigate` gives an analyst a case-management workspace built
on top of Phase 8's findings — see
[docs/architecture/investigation-engine.md](docs/architecture/investigation-engine.md)
for the full architecture. It is an analytical aid: it reasons only over
evidence already collected, never performs a network request, an
exploit, a credential attack, or an automatic remediation action.

```sh
# Open an investigation and attach an initial finding.
ai-surface investigate create --target example.com --title "Suspicious API Surface Change" \
  --created-by analyst1 --finding <finding-id>

# Correlate every finding currently attached to it.
ai-surface investigate correlate <investigation-id>

# Review the timeline, add a note, propose a hypothesis.
ai-surface investigate timeline <investigation-id>
ai-surface investigate note <investigation-id> --content "..." --author analyst1
ai-surface investigate hypothesis <investigation-id> --title "..." --created-by analyst1

# Suggest incident clusters from currently-open findings, and accept one.
ai-surface investigate cluster suggest --target example.com
ai-surface investigate cluster accept <cluster-id> --actor analyst1

# Close, reopen (a reason is required), and export.
ai-surface investigate close <investigation-id> --actor analyst1 --reason "..."
ai-surface investigate reopen <investigation-id> --actor analyst1 --reason "new evidence surfaced"
ai-surface investigate export <investigation-id> --format markdown
```

Every correlation carries an explicit **explanation** and the individual
**signals** that produced its score — never a bare `related: true`. A
relationship is `candidate` (below the configured threshold, still
surfaced for review) or `confirmed` (at/above it); "same IP" and
temporal proximity alone are deliberately scored too low to ever confirm
a relationship by themselves (phase9.md §39's false-correlation
guardrail). An investigation's timeline and audit trail are the same
append-only record — every state change is there, with real observation
timestamps, never fabricated ones. Findings are never removed from an
investigation when resolved; the distinction between active and
historical evidence is always visible.

## Threat Intelligence & Risk Enrichment

`ai-surface intel` and `ai-surface risk` add structured context and a
deterministic risk score on top of everything Phase 2-9 already
collected — see
[docs/architecture/threat-intelligence.md](docs/architecture/threat-intelligence.md)
and [docs/security/risk-model-v1.md](docs/security/risk-model-v1.md) for
the full architecture. Local enrichment (DNS/certificate/technology
context, asset history) works with zero external dependencies; a single
external threat-feed provider exists but is disabled by default —
enabling it requires both `intelligence.external.enabled: true` in
configuration AND the provider's own `intelligence.threat_feed.base_url`/
`api_key_env` to be set (the API key itself is read only from the named
environment variable, never from configuration).

```sh
# Show already-persisted intelligence for an indicator (no provider is queried).
ai-surface intel lookup example.com --target example.com

# Actively enrich an indicator, or preview what would run without making any request.
ai-surface intel enrich example.com --target example.com
ai-surface intel enrich example.com --target example.com --dry-run

# Invalidate cached results and re-enrich; inspect provider health.
ai-surface intel refresh example.com --target example.com
ai-surface intel providers
ai-surface intel status

# Calculate risk for an asset/finding/investigation (always explains itself).
ai-surface risk asset <asset-id>
ai-surface risk finding <finding-id>
ai-surface risk investigation <investigation-id>
ai-surface risk asset <asset-id> --history

# Record analyst context that risk scoring can use (never inferred automatically).
ai-surface risk criticality set <asset-id> --level high --set-by analyst1
```

Every intelligence record carries full **provenance** (which provider,
which version of it, when it was retrieved) and is never presented as
more than what it is: a *provider's* classification, not this platform's
own confirmed finding — a verdict of "malicious" means "a provider
classified this indicator as malicious", nothing more. When providers
disagree, both observations are kept and the conflict is surfaced
explicitly rather than silently resolved. A vulnerability match is only
ever `confirmed` when both the product **and** version evidence support
it; a bare product-name match (no version evidence) is always
`insufficient_evidence`, never a confirmed vulnerability. A risk score is
a combined security-context signal (finding severity, exposure,
vulnerability matches, intelligence, asset criticality, recent change) —
it is explicitly never a claim of confirmed vulnerability, and every
score prints exactly which factors produced it. This platform never
blocks an IP/domain, modifies infrastructure, or infers a threat actor's
identity from intelligence data.

## Detection Engineering

`ai-surface detection` and `ai-surface alert` let an analyst define, version,
test, and evaluate deterministic detection rules against this platform's
own already-normalized findings, asset/endpoint observations, technology
fingerprints, and threat intelligence — see
[docs/architecture/detection-engine.md](docs/architecture/detection-engine.md),
[docs/detection/rule-authoring.md](docs/detection/rule-authoring.md), and
[docs/detection/builtin-rules.md](docs/detection/builtin-rules.md).
There is no raw-log-ingestion pipeline in this platform, so a rule's
"event" is always a projection of a row Phase 2/6/7/8/10 already
persisted, never an external log line.

```sh
# Inspect, test, and install the 5 built-in rules — no database needed to test.
ai-surface detection builtin list
ai-surface detection builtin test high_severity_finding_burst
ai-surface detection builtin install repeated_malicious_intelligence_signal --target example.com --created-by analyst1

# Author your own rule (JSON or YAML — see docs/detection/rule-authoring.md).
ai-surface detection create --target example.com --name my_rule --definition-file my_rule.yaml --created-by analyst1
ai-surface detection evaluate <rule-id> --dry-run --from 2026-01-01T00:00:00Z --to 2026-01-02T00:00:00Z
ai-surface detection enable <rule-id> --actor analyst1

# Work the resulting alerts.
ai-surface alert list
ai-surface alert acknowledge <alert-id>
ai-surface alert suppress <alert-id> --reason "known scanner" --actor analyst1 --duration 30m
ai-surface alert investigate <alert-id> --actor analyst1
```

Four rule types only (`field_match`, `threshold`, `sequence`,
`aggregation`) — never an arbitrary expression language. A rule version
is immutable once created (editing always creates a new version, so a
historical match always remains reproducible); a disabled rule produces
no new matches while its history stays queryable. Every match carries
its evidence (which events caused it) and a human-readable explanation —
never a bare "rule matched". Suppressing a match or alert always
requires a reason and never deletes the underlying evidence. Promoting
an alert to a Phase 9 investigation automatically attaches its evidence
and a timeline event — no manual reconstruction needed. This platform
implements no autonomous response and no offensive automation of any
kind.

## Advanced Correlation

`ai-surface correlation` and `ai-surface chain` link this platform's
individual signals — findings, Phase 11 detection matches/alerts, Phase
10 intelligence, assets — into higher-level correlated activity and, when
the evidence classifies into a recognizable sequence, an attack chain.
See [docs/architecture/correlation-engine.md](docs/architecture/correlation-engine.md),
[docs/detection/correlation-strategies.md](docs/detection/correlation-strategies.md),
and [docs/investigation/attack-chains.md](docs/investigation/attack-chains.md).
A correlation is never presented as a confirmed attack on its own —
`confirmed`/`dismissed` are always an explicit analyst action.

```sh
# Evaluate a target's recent observations — deterministic, explainable.
ai-surface correlation evaluate --target example.com --from 2026-01-01T00:00:00Z --to 2026-01-02T00:00:00Z

ai-surface correlation list
ai-surface correlation show <id>
ai-surface correlation graph <id>       # nodes, edges, confidence, observed vs. inferred
ai-surface correlation timeline <id>    # unified, chronologically-ordered evidence
ai-surface correlation evidence <id>

# Analyst judgment — never automatic.
ai-surface correlation confirm <id> --actor analyst1
ai-surface correlation dismiss <id> --actor analyst1 --reason "known automation"
ai-surface correlation merge <survivor-id> <source-id...>
ai-surface correlation split <id> --node <node-id> --actor analyst1
ai-surface correlation investigate <id> --actor analyst1   # attach to a Phase 9 investigation

# Attack chains — a narrative view, not proof of an attack.
ai-surface chain list
ai-surface chain show <id>
ai-surface chain explain <id>
```

Six strategies (`asset`, `temporal`, `identity`, `network`, `detection`,
`intelligence`) each produce explained, confidence-scored edges, marked
`observed` or `inferred` — never collapsed into an unexplained "related:
true". A correlation's `Score`/`Confidence`/`Severity` are three distinct
axes, documented in `internal/correlation/scoring.go`. This platform
implements no autonomous response, no offensive automation, and no
automatic threat attribution.

## AI Investigation Assistant

`ai-surface ai` is an **analyst assistant, not an autonomous security
operator** (disabled by default). It reasons only over evidence already
persisted by Phases 2-12 — findings, alerts, detection matches,
correlations, attack chains, intelligence, timeline, notes — through a
narrow set of read-only tools, and every claim it makes is either directly
cited to that evidence or explicitly labeled `Inferred`/`Unknown`. See
[docs/architecture/ai-assistant.md](docs/architecture/ai-assistant.md),
[docs/ai/safety.md](docs/ai/safety.md), and
[docs/ai/investigation-guide.md](docs/ai/investigation-guide.md).

```sh
ai-surface ai status

ai-surface ai summarize <investigation-id> --actor analyst1
ai-surface ai analyze <investigation-id> --actor analyst1      # timeline
ai-surface ai questions <investigation-id> --actor analyst1
ai-surface ai report <investigation-id> --actor analyst1 --save-as-note

ai-surface ai explain-alert <alert-id> --actor analyst1
ai-surface ai explain-detection <detection-match-id> --actor analyst1
ai-surface ai analyze-correlation <correlation-id> --actor analyst1
ai-surface ai analyze-correlation <correlation-id> --actor analyst1 --chain

# A bounded, session-scoped conversation.
ai-surface ai session new --investigation <id> --actor analyst1
ai-surface ai chat <session-id> "What evidence is missing?"

# AI-generated notes are always unapproved until an analyst says otherwise.
ai-surface ai note approve <note-id> --approver analyst1
```

Citations are validated against the exact evidence supplied — a
fabricated reference is always removed, never presented as real. The
platform is fully usable with the built-in `mock` provider and zero
external dependency; an OpenAI-compatible provider is an explicit opt-in
(`ai.provider.name: openai`), and every credential is read from an
environment variable, never from configuration. Nothing in this phase
changes an alert's severity, an investigation's status, a correlation's
confirmation state, or a risk score — those remain exclusively analyst
actions.

## Security Analytics & Reporting

`ai-surface analytics`, `ai-surface report`, `ai-surface evidence-package`, and
`ai-surface control` turn Phase 2-13's own data into dashboards, trend
analysis, and exportable reports — never a duplicate copy of any
existing model. See
[docs/architecture/ai-assistant.md](docs/architecture/ai-assistant.md)'s
sibling docs for this phase:
[docs/analytics/metrics.md](docs/analytics/metrics.md),
[docs/analytics/dashboards.md](docs/analytics/dashboards.md),
[docs/reporting/reports.md](docs/reporting/reports.md), and
[docs/compliance/evidence.md](docs/compliance/evidence.md).

```sh
# Dashboards — read-only aggregates over existing data.
ai-surface analytics overview --target example.com
ai-surface analytics risk --target example.com --range 30d
ai-surface analytics alerts --target example.com --range 7d
ai-surface analytics posture --target example.com   # derived from risk data — not an objective security score

# Reports — versioned, citation-validated, never overwriting an earlier version.
ai-surface report create --target example.com --type executive --actor analyst1
ai-surface report create --target example.com --type investigation --subject <investigation-id> --actor analyst1
ai-surface report approve <report-id> --approver analyst1   # an explicit, distinct action — never automatic
ai-surface report export <report-id> --format csv           # secrets redacted, spreadsheet-injection-safe

# Evidence packages — scoped to one report's own cited evidence only.
ai-surface evidence-package create --report <report-id> --actor analyst1
ai-surface evidence-package manifest <package-id>            # item id, type, SHA-256 hash, timestamp

# Generic control evidence — no compliance framework or certification claim.
ai-surface control record --target example.com --control AC-2 --evidence-type finding --reference <id> --description "..."
ai-surface control list --target example.com                 # controls with evidence; a gap is represented by absence
```

Analytics results are cached briefly, in-process, always keyed by
target — a cache entry for one target can never be returned for another.
This platform makes no compliance certification claims anywhere in this
output; `control` evidence is a generic, analyst-populated ledger, never
a framework mapping this platform invents on its own.

## Executables

| Command       | Purpose                                                     |
| ------------- | ------------------------------------------------------------ |
| `cmd/server`  | HTTP API server (`/health`, `/live`, `/ready` — no other REST surface exists) |
| `cmd/cli`     | `ai-surface` CLI (`version`, `config validate`, `health`, `target`, `asset`, `scan`, `network-scan`, `dns-scan`, `subdomain-scan`, `fingerprint`, `endpoint-scan`, `findings`, `investigate`, `intel`, `risk`, `detection`, `alert`, `correlation`, `chain`, `ai`, `analytics`, `report`, `evidence-package`, `control`) |
| `cmd/worker`  | Background worker: verifies Postgres/Redis, graceful shutdown |
| `cmd/migrate` | Database migration runner (`up`, `status`, `version`)         |

`ai-surface asset` (and `target create`/`target list`) remain development
diagnostics for exercising the Phase 2 persistence layer by hand (see
their `--help`); `ai-surface target authorize`, `ai-surface scan`,
`ai-surface network-scan`, `ai-surface dns-scan`/`subdomain-scan`,
`ai-surface fingerprint`, `ai-surface endpoint-scan`, `ai-surface findings`,
`ai-surface investigate`, `ai-surface intel`, `ai-surface risk`,
`ai-surface detection`, `ai-surface alert`, `ai-surface correlation`,
`ai-surface chain`, `ai-surface ai`, `ai-surface analytics`, `ai-surface report`,
`ai-surface evidence-package`, and `ai-surface control` are real, required
parts of running Phase 3/4/5/6/7/8/9/10/11/12/13/14.

## Production readiness

Phase 15 hardened this platform without changing its functional scope —
see [docs/security/final-audit.md](docs/security/final-audit.md) for
every finding (with evidence) and
[docs/operations/production-readiness-report.md](docs/operations/production-readiness-report.md)
for the resulting scorecard and verdict. Start with
[docs/operations/production-readiness.md](docs/operations/production-readiness.md)
and [docs/operations/deployment.md](docs/operations/deployment.md) before
running this anywhere beyond local development.

## License

No license file exists in this repository yet — this is an explicit,
undecided choice left to the project owner (see phase15.md §117), not an
oversight. Do not assume any particular license applies until one is
added.

## Further reading

- [SECURITY.md](SECURITY.md) — authorization boundary, safe defaults
- [docs/architecture/asset-model.md](docs/architecture/asset-model.md) —
  Phase 2 asset model, identity/deduplication, persistence architecture
- [docs/architecture/http-discovery.md](docs/architecture/http-discovery.md) —
  Phase 3 HTTP discovery engine: scope, concurrency, AI candidate
  detection, redirect handling
- [docs/architecture/network-discovery.md](docs/architecture/network-discovery.md) —
  Phase 4 network discovery engine: TCP connect scanning, CIDR expansion,
  service/AI candidate detection
- [docs/architecture/dns-discovery.md](docs/architecture/dns-discovery.md) —
  Phase 5 DNS & subdomain discovery engine: resolver abstraction, record
  types, wildcard detection, TXT secret redaction, historical DNS tracking
- [docs/architecture/fingerprinting.md](docs/architecture/fingerprinting.md) —
  Phase 6 passive fingerprinting engine: signature format, matching,
  scoring, conflict handling, AI/database candidate handling, historical
  fingerprint tracking
- [docs/architecture/endpoint-discovery.md](docs/architecture/endpoint-discovery.md) —
  Phase 7 endpoint & API discovery engine: bounded crawling, scope
  enforcement, HTML/JavaScript extraction, OpenAPI/Swagger/GraphQL,
  documented-vs-observed-vs-inferred, historical endpoint tracking
- [docs/architecture/finding-detection.md](docs/architecture/finding-detection.md) —
  Phase 8 finding & vulnerability detection engine: detector interface/
  registry, finding identity/lifecycle/diff, severity vs. confidence,
  passive vs. safe-active detection, evidence redaction
- [docs/architecture/investigation-engine.md](docs/architecture/investigation-engine.md) —
  Phase 9 investigation & correlation engine: case management, timeline,
  correlation rules/scoring/explainability, incident clusters,
  hypotheses, evidence provenance, export
- [docs/architecture/threat-intelligence.md](docs/architecture/threat-intelligence.md) —
  Phase 10 threat intelligence & risk engine: provider interface/registry,
  indicator normalization, provenance, caching, reputation aggregation,
  vulnerability matching, external-provider opt-in policy
- [docs/security/risk-model-v1.md](docs/security/risk-model-v1.md) —
  the risk-scoring model's factors, weights, normalization, and
  reproducible worked examples
- [docs/architecture/detection-engine.md](docs/architecture/detection-engine.md) —
  Phase 11 detection rule engine: rule language/schema/validation/
  compilation, threshold/sequence/aggregation evaluation, deduplication,
  suppression, alert lifecycle, investigation/risk integration
- [docs/detection/rule-authoring.md](docs/detection/rule-authoring.md) —
  worked examples for every rule type plus the testing/deployment
  workflow
- [docs/detection/builtin-rules.md](docs/detection/builtin-rules.md) —
  purpose, logic, and false-positive guidance for all 5 built-in rules
- [docs/architecture/correlation-engine.md](docs/architecture/correlation-engine.md) —
  Phase 12 correlation engine: strategies, graph model, scoring/
  confidence/severity, deduplication, merge/split, limits, performance
- [docs/detection/correlation-strategies.md](docs/detection/correlation-strategies.md) —
  purpose, matching logic, and false-positive guidance for all 6
  built-in correlation strategies
- [docs/investigation/attack-chains.md](docs/investigation/attack-chains.md) —
  attack-chain model, stage classification, confidence weighting, gaps,
  analyst confirmation
- [docs/architecture/ai-assistant.md](docs/architecture/ai-assistant.md) —
  Phase 13 AI assistant: provider abstraction, context builder, tool
  system, prompt architecture, citation/validation pipeline, sessions
- [docs/ai/safety.md](docs/ai/safety.md) — prompt injection defense, trust
  boundaries, secret handling, tool authorization, hallucination defense,
  attribution policy
- [docs/ai/investigation-guide.md](docs/ai/investigation-guide.md) —
  worked examples for every AI task, sessions/chat, and provider
  configuration
- [docs/analytics/metrics.md](docs/analytics/metrics.md) — Phase 14
  metric definitions: calculation, source, filters, time semantics,
  limitations for every dashboard number
- [docs/analytics/dashboards.md](docs/analytics/dashboards.md) —
  dashboard types/presets, filters, caching, drill-down, CLI adaptation
- [docs/reporting/reports.md](docs/reporting/reports.md) — report types,
  lifecycle, versioning, approval, export, citation validation, content
  security
- [docs/compliance/evidence.md](docs/compliance/evidence.md) — the
  generic control-evidence model, evidence freshness, and why no
  compliance framework or certification is claimed
- [docs/security/threat-model.md](docs/security/threat-model.md) —
  Phase 15 trust boundaries, threats, mitigations, and residual risk
- [docs/security/production-hardening.md](docs/security/production-hardening.md) —
  the concrete hardening checklist this platform's own code actually
  implements, by area
- [docs/security/final-audit.md](docs/security/final-audit.md) — every
  Phase 15 audit finding, with evidence, remediation, and status
- [docs/security/final-security-checklist.md](docs/security/final-security-checklist.md) —
  a flat pass/fail security checklist
- [docs/operations/production-readiness.md](docs/operations/production-readiness.md) —
  environments, infrastructure, configuration, secrets, and upgrade/
  rollback procedure
- [docs/operations/deployment.md](docs/operations/deployment.md) — how to
  actually deploy: database, migrations, reverse proxy/TLS, health checks
- [docs/operations/disaster-recovery.md](docs/operations/disaster-recovery.md) —
  failure scenarios, backup/restore, RTO/RPO targets
- [docs/operations/runbook.md](docs/operations/runbook.md) — what to do
  when something is actually down
- [docs/operations/troubleshooting.md](docs/operations/troubleshooting.md) —
  real errors this platform produces and what they mean
- [docs/architecture/overview.md](docs/architecture/overview.md) — the
  whole-system architecture and security-boundary diagrams
- [CONTRIBUTING.md](CONTRIBUTING.md) — development setup, tests,
  formatting, security requirements for contributions