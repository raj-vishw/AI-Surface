# Final Security Checklist

Each item below is checked against actual evidence gathered this phase —
see `docs/security/final-audit.md` for the finding details behind any
item marked "fixed this phase," and `docs/security/threat-model.md` for
the reasoning behind any item marked "not applicable."

## Authentication

- [x] No authentication mechanism exists — confirmed by inspection, and
      documented as an architectural characteristic rather than a defect
      (SEC-01, `docs/security/threat-model.md` T1).
- [N/A] Password hashing, session management, token expiration/refresh —
      not applicable; no password/session/token concept exists.

## Authorization

- [x] No RBAC exists — target-scoping (`TargetID` checks) is the one
      enforced boundary; verified by
      `internal/service/reporting/isolation_test.go` (SEC-11).
- [x] Server-side enforcement only — every check that exists
      (`apperrors.NewForbidden` call sites) runs in the service layer,
      never trusted from a caller-supplied flag alone.

## Secrets

- [x] `gitleaks detect` run against the working tree: clean (after
      allowlisting this platform's own redaction-engine test fixtures —
      see `.gitleaks.toml`).
- [x] No hard-coded credential found anywhere in `.go`/`.yaml` source
      (manual grep audit, this phase).
- [x] Every credential-shaped config field reads from an environment
      variable only (`internal/config`), never a file or the database.
- [x] `.env.example` exists, contains only placeholder values, and is
      now correctly tracked in git (SEC-03, fixed this phase).

## APIs

- [x] The only network-facing endpoints (`/health`, `/live`, `/ready`)
      require no authentication by design (they carry no sensitive data
      — status only) and now carry defensive response headers (SEC-09).
- [N/A] Rate limiting on a general REST API — no such API exists beyond
      the three health endpoints; `internal/service/ai`'s own
      per-user/per-target/concurrent rate limiting (Phase 13) remains
      unchanged and unaffected.

## Database

- [x] No SQL injection vector found — every value is parameterized; every
      `fmt.Sprintf`-built query interpolates only fixed identifiers
      (audited this phase, 21 call sites, `docs/security/
      production-hardening.md`).
- [x] `database.ssl_mode` now defaults to `require` in the new
      `configs/production/config.yaml`, and `disable` is startup-fatal
      when `AI_SURFACE_APP_ENV=production` (SEC-08, fixed and tested).
- [x] Connection pool bounds configured
      (`max_open_connections`/`max_idle_connections`/lifetimes).

## Network

- [x] SSRF: outbound HTTP requests now refuse link-local/cloud-metadata
      addresses at dial time, immune to DNS rebinding (SEC-04, fixed and
      tested — `internal/httpclient/ssrf_test.go`).
- [x] No command execution anywhere in this codebase (`os/exec` grep:
      zero results) — no command-injection attack surface exists.
- [x] No path traversal vector found — no filesystem path in this
      codebase is ever derived from untrusted (target/network) input.

## AI

- [x] Prompt-injection defenses unchanged from Phase 13 (structured
      `Fact`s, not raw target text) and re-verified functioning
      (`internal/ai`'s test suite: pass).
- [x] Tool allowlist / read-only tools unchanged and re-verified.
- [x] Secret redaction (`internal/ai.Redact`) re-verified via
      `internal/reporting`'s reuse of it (export tests pass).
- [x] Citation validation (`internal/ai.ValidateCitations`) re-verified
      via `internal/reporting`'s reuse of it.
- [x] `ai.enabled: false` remains the shipped default in every
      environment; confirmed no core security pipeline imports
      `internal/ai` (grep audit, this phase — zero results under
      `internal/detection`, `internal/correlation`, `internal/
      investigation`, `internal/intelligence`).

## Exports

- [x] XSS: not applicable (no HTML rendering anywhere in this codebase);
      JSON export relies on `encoding/json`'s default HTML-escaping
      (tested, `TestEncodeJSON_EscapesHTMLByDefault`).
- [x] CSV injection: `EscapeCSVValue` applied to every cell (tested,
      `internal/reporting/csv_test.go`).
- [x] Secret redaction applied at both generation and export time
      (tested).
- [x] Evidence-package manifests are SHA-256 hashed, scoped to only the
      generating report's own referenced evidence (never a full dump).

## Logging

- [x] No secret ever passed to a logger call anywhere in this codebase
      (grep audit, this phase).
- [x] Production defaults to `info` level; `debug` is now startup-fatal
      in production (SEC-08).
- [x] Structured JSON logging with request IDs (`internal/httpserver`,
      `internal/logging`) — unchanged, re-verified this phase.

## Dependencies

- [x] `govulncheck ./...`: 6 standard-library vulnerabilities found,
      all fixed by bumping the Go toolchain to 1.26.6 (SEC-05); re-run
      after the fix: "No vulnerabilities found."
- [x] `go.mod`/`go.sum` third-party dependencies: 0 vulnerabilities
      (`govulncheck`/`trivy fs` both confirm).
- [x] CI now runs `govulncheck` on every push/PR (SEC-07).

## Deployment

- [x] `deployments/docker/Dockerfile.server` uses a pinned multi-stage
      build, a distroless nonroot runtime image, and no secrets baked
      into build args — confirmed by inspection and by `trivy fs
      --scanners misconfig` against the Dockerfile (0 findings).
- [x] `.dockerignore` correctly excludes `.env`/build artifacts/docs
      from the build context.
- [ ] Container image vulnerability scan (Trivy, against the actual
      built image): CI step added this phase but **not executed** in
      this sandbox (no Docker daemon access — SEC-07's own entry records
      this honestly). Must be verified on the first CI run with Docker
      access, or manually by an operator with Docker before first
      production deployment.

## Backups

- [x] Backup/restore procedure documented
      (`docs/operations/disaster-recovery.md`).
- [ ] Restore actually tested against a live database: **not done**
      (SEC-14) — no PostgreSQL instance reachable in this sandbox. Open
      item for the first real deployment.
