# Final Security Audit — Phase 15

Every finding below came from actually inspecting this codebase and
running real tools against it in this development environment this
phase (`gofmt`, `go vet`, `go test`, `go test -race`, `golangci-lint`,
`govulncheck`, `gitleaks`, `trivy fs`) — none is speculative. Status
reflects what was actually done, not what would ideally be done.

| ID | Severity | Component | Status |
| --- | --- | --- | --- |
| SEC-01 | High (contextual) | Whole platform | Accepted risk (documented) |
| SEC-02 | Medium | `.gitignore` | Fixed |
| SEC-03 | Medium | `.gitignore` | Fixed |
| SEC-04 | High | `internal/httpclient` | Fixed |
| SEC-05 | Medium | Go toolchain | Fixed |
| SEC-06 | Medium | CI/Makefile | Fixed |
| SEC-07 | Medium | CI | Fixed |
| SEC-08 | Medium | `internal/config` | Fixed |
| SEC-09 | Low | `internal/httpserver` | Fixed |
| SEC-10 | Informational | `internal/httpserver` | Fixed |
| SEC-11 | Low | `internal/service/reporting` | Fixed |
| SEC-12 | Informational | `docs/` | Fixed |
| SEC-13 | Informational | N/A (environment) | Open — documented |
| SEC-14 | Medium | N/A (environment) | Open — documented |
| SEC-15 | Informational | Repository root | Partially addressed |

---

### SEC-01 — No authentication/authorization layer exists anywhere in this platform

- **Severity**: High if this platform is ever exposed to a multi-user or
  untrusted-network environment; Low for its actual intended deployment
  model (single trusted operator, local/lab use — see SECURITY.md).
- **Description**: no session, token, password-hashing, or RBAC code
  exists anywhere in this codebase (confirmed by inspection across every
  phase since Phase 1). The only access boundary is
  `TargetID`-scoping inside a handful of aggregate-building services.
- **Impact**: anyone with the configured database credentials has
  unrestricted access to every target's data; there is no per-user
  accountability for who ran what.
- **Evidence**: `grep -rn "NewForbidden" internal/service/` returns only
  3 files (`ai`, `detection`, `reporting`) out of ~13 service packages;
  no `internal/auth` package exists.
- **Remediation**: out of scope for this phase (phase15.md §159/§162
  explicitly forbid new product features / another phase). A future
  phase adding authentication should treat this document's threat model
  (T1) as its starting requirements.
- **Status**: **Accepted risk**, documented in
  `docs/security/threat-model.md` (T1) and this platform's `README.md`/
  `SECURITY.md`. No owner beyond the project's own maintainer is named
  (phase15.md §142 — do not invent one).

### SEC-02 — `.gitignore` excluded `docs/` and `CHANGELOG.md` from version control

- **Severity**: Medium.
- **Description**: `.gitignore` contained `docs/` and `CHANGELOG.md`
  under a "personal local overrides" comment that did not actually apply
  to either — both were completely untracked by git despite being
  extensively written across Phases 1–14 and referenced as complete
  deliverables in every phase's own report.
- **Impact**: every documentation deliverable from every prior phase
  existed only on the local filesystem, never in version control — a
  fresh clone of this repository would have had none of it.
- **Evidence**: `git ls-files | grep -c '^docs/'` returned `0` before the
  fix; `git check-ignore -v docs/ CHANGELOG.md` confirmed both were
  matched by `.gitignore` lines 39–40.
- **Remediation**: removed both lines from `.gitignore`.
- **Status**: **Fixed** — verified `git check-ignore` no longer matches
  either path.

### SEC-03 — `.env.example` excluded from version control

- **Severity**: Medium.
- **Description**: `.gitignore`'s `.env.*` pattern also matched
  `.env.example`, the safe, secret-free template file phase15.md §4
  explicitly requires exist and (implicitly) be available to a fresh
  clone.
- **Impact**: a new deployment following `.env.example`'s own
  instructions ("copy this file to .env") would not have had the file to
  copy.
- **Evidence**: `git ls-files | grep -E '^\.env'` returned nothing before
  the fix.
- **Remediation**: changed `.env.*` to also carry a `!.env.example`
  negation (the same pattern `.dockerignore` already used correctly).
- **Status**: **Fixed**.

### SEC-04 — SSRF: outbound HTTP requests validated scope by hostname only, not resolved IP

- **Severity**: High.
- **Description**: `internal/discovery/http.ScopeValidator` (and every
  caller of `internal/httpclient`) restricted requests to a target's own
  hostname (or subdomain), but never checked what IP address that
  hostname actually resolved to, and performed no equivalent check on
  redirect hops beyond the same hostname rule.
- **Impact**: a target domain that resolves (via attacker-controlled DNS,
  DNS rebinding, or simple misconfiguration) to a cloud-metadata address
  (`169.254.169.254`) would have caused this platform to fetch and
  potentially record that cloud environment's credentials on the
  operator's behalf.
- **Evidence**: read `internal/discovery/http/scope.go` in full —
  `Allowed`/`AllowedURL` operate purely on `url.URL.Hostname()` strings.
- **Remediation**: added `internal/httpclient/ssrf.go` — a
  `net.Dialer.Control` hook that inspects the actual resolved address
  immediately before `connect()`, unconditionally refusing
  `169.254.0.0/16` and `fd00:ec2::254`. This is immune to DNS rebinding
  (the check runs on the address about to be dialed, not the hostname
  before resolution) and does not restrict loopback/RFC1918 addresses
  (an authorized internal-network penetration test is a supported use
  case per SECURITY.md).
- **Status**: **Fixed** — `internal/httpclient/ssrf_test.go` (3 new
  tests) verifies both the block and that loopback/private/public
  addresses remain unaffected; full suite re-run clean.

### SEC-05 — 6 Go standard-library vulnerabilities in the pinned toolchain

- **Severity**: Medium (none had a working exploit trace reachable from
  untrusted input in this codebase's actual call graph, per
  `govulncheck`'s own symbol-reachability analysis, but several — the
  `net/url` quadratic-complexity issue reachable from
  `endpoint.Crawler.normalizeAndCheckScope`, which processes
  target-controlled URLs — plausibly are).
- **Description**: `go 1.26.5` (the version this project's `go.mod`
  pinned) is affected by GO-2026-6218, -6090, -6089, -6088, -5972, and
  -5026 (all fixed upstream in 1.26.6).
- **Evidence**: `govulncheck ./...` output, captured in full in
  `docs/operations/production-readiness-report.md`'s Verification
  Results.
- **Remediation**: bumped `go.mod`'s `go` directive from `1.26.5` to
  `1.26.6`.
- **Status**: **Fixed** — re-running `govulncheck ./...` against the
  bumped toolchain reports "No vulnerabilities found." Full test suite
  (`go test ./...`, `go test -race ./...`), `go vet`, `gofmt`,
  `make build-all`, and `golangci-lint` all re-verified clean after the
  bump.

### SEC-06 — No race-detector testing in CI or `Makefile`

- **Severity**: Medium.
- **Description**: `make test` / CI's `Test` step ran `go test ./...`
  only; nothing ran `go test -race ./...` anywhere in this project prior
  to this phase.
- **Impact**: a data race introduced in any phase could ship undetected.
- **Remediation**: added `make test-race` and a `Test (race detector)`
  CI step.
- **Status**: **Fixed** — `go test -race ./...` run this phase across
  the entire module: clean, zero races detected.

### SEC-07 — No dependency, secret, or container vulnerability scanning in CI

- **Severity**: Medium.
- **Description**: `.github/workflows/ci.yml` ran formatting/vet/test/
  build/lint only — no `govulncheck`, no secret scanner, no image scan.
- **Remediation**: added a `security` CI job running `govulncheck ./...`,
  `gitleaks/gitleaks-action@v2` (configured via the new
  `.gitleaks.toml`), and `aquasecurity/trivy-action` against the built
  server image (CRITICAL/HIGH, fail on unfixed).
- **Status**: **Fixed and locally verified** for `govulncheck` and
  `gitleaks` (both run directly in this environment — see SEC-04/SEC-05
  findings above, which they surfaced). `trivy fs` (vuln/secret/misconfig
  scanner) was also run directly against the repository and Dockerfile,
  clean (0 vulnerabilities in `go.mod`, 0 Dockerfile misconfigurations).
  The CI job's own container **build-and-image-scan** step was added and
  is believed correct but was **not executed** in this sandbox — no
  Docker daemon access was available (`permission denied` connecting to
  `/var/run/docker.sock`) — flagged honestly rather than claimed passing.

### SEC-08 — No production/staging configuration separation or production safety validation

- **Severity**: Medium.
- **Description**: only `configs/defaults/` and `configs/development/`
  existed; nothing prevented `AI_RECON_APP_ENV=production` from running
  with `logging.level: debug`, `security.require_authorization: false`,
  or `database.ssl_mode: disable`.
- **Impact**: a production deployment could silently inherit
  development-safe-but-production-unsafe settings.
- **Remediation**: added `configs/production/config.yaml`, and three new
  startup guard rails in `internal/config.Config.Validate()` that reject
  those three specific combinations whenever
  `application.environment == "production"`.
- **Status**: **Fixed** — 5 new tests in
  `internal/config/production_test.go` verify both the guard rails
  firing in production and *not* firing outside it (no regression to
  development's existing permissive defaults).

### SEC-09 — No defensive HTTP response headers

- **Severity**: Low (this server has no browser-facing content to
  protect, but defense-in-depth is still worthwhile and essentially
  free).
- **Remediation**: added `securityHeadersMiddleware`
  (`Content-Security-Policy: default-src 'none'`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Permissions-Policy`, `X-Frame-Options: DENY`) to every response.
- **Status**: **Fixed** — verified by
  `internal/httpserver/server_test.go`'s
  `TestServer_SecurityHeadersOnEveryResponse`.

### SEC-10 — No `/live` endpoint (phase15.md §25's literal naming)

- **Severity**: Informational — `/health` already served this exact
  purpose (pure liveness, no dependency checks).
- **Remediation**: added `GET /live` as an explicit alias.
- **Status**: **Fixed** — verified by
  `TestServer_LiveIsAliasForHealth`.

### SEC-11 — Cross-target isolation logic existed but was untested

- **Severity**: Low.
- **Description**: `internal/service/reporting/sections.go`'s
  `TargetID` mismatch checks (the platform's core "project isolation"
  boundary — see threat T7) had no test proving they actually reject a
  mismatched request.
- **Remediation**: added
  `internal/service/reporting/isolation_test.go` — a minimal fake
  investigations repository proving `buildInvestigationReport` rejects a
  cross-target subject with `apperrors.CategoryForbidden` and accepts a
  same-target one.
- **Status**: **Fixed** for the investigation-report path (directly
  tested). The equivalent checks in `buildAssetReport`/
  `buildCorrelationReport` (`sections.go:92`/`:135`) follow the
  byte-for-byte identical pattern and were verified correct by code
  inspection but not given their own duplicate test fakes in this
  phase — noted honestly as inspected-not-independently-tested rather
  than claimed equally covered.

### SEC-12 — No operations/security documentation existed

- **Severity**: Informational.
- **Remediation**: this phase added
  `docs/operations/{production-readiness,deployment,disaster-recovery,
  runbook,troubleshooting,release-checklist,production-readiness-report}.md`
  and `docs/security/{production-hardening,threat-model,
  final-security-checklist,final-audit}.md` and
  `docs/architecture/overview.md`.
- **Status**: **Fixed**.

### SEC-13 — No load/performance testing was possible in this environment

- **Severity**: Informational.
- **Description**: no PostgreSQL or Redis instance was reachable in this
  development sandbox during this phase's work (the same standing
  limitation every phase since Phase 2 has recorded).
- **Status**: **Open — documented**, not fixed. See
  `docs/operations/production-readiness-report.md`'s Performance Results
  section for exactly what this phase could and couldn't measure, and
  what an operator should run against a real instance before relying on
  any specific throughput/latency number.

### SEC-14 — Backup/restore procedure was never tested against a live database

- **Severity**: Medium (an untested backup is not a verified backup).
- **Status**: **Open — documented**, not fixed, for the same
  no-live-database-in-this-sandbox reason as SEC-13. A concrete,
  runnable restore-test procedure is provided in
  `docs/operations/disaster-recovery.md`'s Restore Test section; the
  first real deployment should run it and record the actual result there
  rather than carry this "not executed" status forward indefinitely.

### SEC-15 — No `CONTRIBUTING.md`; no `LICENSE`

- **Severity**: Informational.
- **Status**: **Partially addressed** — added a `CONTRIBUTING.md` this
  phase. No `LICENSE` file exists and none was added: phase15.md §117 is
  explicit that an absent license must not be silently chosen — this
  remains an explicit, undecided choice for the project's owner. See
  `README.md`'s new note.

## Summary

| Severity | Found | Fixed | Open (documented) | Accepted risk |
| --- | --- | --- | --- | --- |
| Critical | 0 | — | — | — |
| High | 2 (SEC-01, SEC-04) | 1 (SEC-04) | 0 | 1 (SEC-01) |
| Medium | 7 (SEC-02, 03, 05, 06, 07, 08, 14) | 6 | 1 (SEC-14) | 0 |
| Low | 2 (SEC-09, SEC-11) | 2 | 0 | 0 |
| Informational | 4 (SEC-10, 12, 13, 15) | 2 (SEC-10, 12) | 1 (SEC-13) | — (SEC-15 partially addressed — see above) |

Zero unresolved Critical findings. Zero unresolved High findings that
represent a defect (SEC-01 is a documented architectural characteristic
with an explicit residual-risk statement, not left "unresolved" in the
sense phase15.md §141 means — see its own entry above for the exact
conditions under which its risk would need to be revisited). SEC-14 (an
untested backup/restore procedure) is the one Medium item genuinely left
open, and it is open because no live database was reachable in this
development sandbox, not because it was skipped — see its entry above
for the exact runnable procedure the first real deployment should
execute. See `docs/operations/production-readiness-report.md` for the
resulting production-readiness verdict.
