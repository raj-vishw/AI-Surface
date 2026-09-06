# Contributing

This is a single-maintainer project built incrementally, phase by phase
(see `CHANGELOG.md` for the full history). These notes exist for anyone
picking the codebase up later — including future-you.

## Development setup

```sh
cp .env.example .env        # adjust as needed; .env is gitignored
make dev-up                 # PostgreSQL + Redis + server, via docker compose
go run ./cmd/migrate up     # apply migrations
go run ./cmd/cli --help     # explore available commands
```

See `docs/operations/deployment.md` for the full configuration/deployment
picture, and `README.md` for a functional tour of what each phase added.

## Branch expectations

Work directly on a short-lived branch off `main` for anything beyond a
trivial fix; `main` is the branch CI runs against and the one every
deployment doc assumes is deployable.

## Tests

```sh
make test        # go test ./...
make test-race   # go test -race ./... — required before merging anything
                  # touching concurrent code (goroutines, shared state)
```

New code should come with tests exercising it — every prior phase's
report records the specific tests added; follow that precedent rather
than leaving new logic untested. Prefer a small hand-written fake over a
mocking framework for repository/service interfaces (see
`internal/service/reporting/reporting_test.go` for the established
pattern) — no mocking library is a dependency of this project.

## Formatting and linting

```sh
make fmt         # gofmt -l -w .   — run before every commit
make fmt-check   # what CI actually runs (fails on any unformatted file)
make vet         # go vet ./...
make lint        # golangci-lint run ./...  (must be installed separately)
```

`.golangci.yml` enables `gosec` — an ignored error needs `_ = expr`, not
just a `//nolint:errcheck` comment (gosec doesn't honor that linter's own
nolint directive).

## Security requirements

Before opening a PR that touches anything security-relevant (input
handling, outbound network requests, secrets, SQL, exports), read
`docs/security/production-hardening.md` and
`docs/security/threat-model.md` first, and run:

```sh
make security-check   # govulncheck + gitleaks (both must be installed separately)
```

Never commit a real credential, even a test one that happens to be valid
against a real service — see `.gitleaks.toml` for how this repository's
own deliberately-fake redaction-test fixtures are allowlisted, and follow
that pattern (a documented allowlist entry, never a broadened scanner
config) if a new test genuinely needs a secret-shaped string.

## Pull request expectations

- `make fmt-check vet test test-race lint` (or the CI job that runs all
  of them) passing.
- A short note on what changed and why — this project's `CHANGELOG.md`
  entries (one per phase) are the model to follow for anything
  significant enough to mention there.
- No new functionality that duplicates an existing engine — check
  `docs/architecture/overview.md`'s component table first; most new
  needs are better served by extending an existing package than adding a
  parallel one.
