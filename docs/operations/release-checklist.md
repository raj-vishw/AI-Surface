# Release Checklist

Use this before tagging/deploying a release. Check off each item against
real evidence (a command's actual output, a document section), not by
assumption.

- [ ] Configuration reviewed (`docs/operations/production-readiness.md`,
      `docs/security/production-hardening.md`)
- [ ] Secrets verified (present in the target environment's secret store,
      absent from the repository — `make secret-scan` clean)
- [ ] Database migrations verified (`go run ./cmd/migrate status` shows
      the expected pending set before `up`, and none pending after)
- [ ] Backups verified (a backup exists for the current database state
      before deploying)
- [ ] Restore tested (see `docs/operations/disaster-recovery.md`'s
      Restore Test section — record pass/fail; do not skip this line item
      silently)
- [ ] Tests passing (`make test`)
- [ ] Race tests passing (`make test-race`)
- [ ] Security tests passing (project-isolation/export-security tests —
      see `docs/security/final-security-checklist.md`)
- [ ] Dependency scan passing (`make vuln-check` / CI's `security` job)
- [ ] Secret scan passing (`make secret-scan` / CI's `security` job)
- [ ] Container scan passing where applicable (CI's Trivy image-scan step)
- [ ] Documentation updated (README, CHANGELOG, any doc referencing a
      behavior this release changes)
- [ ] Version assigned (`VERSION` file; see Versioning below)
- [ ] Changelog updated (`CHANGELOG.md`)
- [ ] Deployment tested (a real or staging-equivalent deploy of this
      exact build)
- [ ] Rollback tested (see `docs/operations/deployment.md`'s Rollback
      section — has the previous version actually been redeployed
      successfully in this cycle, or only documented as possible?)
- [ ] Health checks verified (`/health`, `/live`, `/ready` all checked
      against the deployed build)
- [ ] Observability verified (structured logs flowing to your
      aggregator, request IDs present)
- [ ] Critical security findings resolved (`docs/security/final-audit.md`
      — zero unresolved Critical; every High either fixed or explicitly
      risk-accepted with a documented owner)

## Versioning

`VERSION` (currently `0.1.0`) plus the git commit SHA and build timestamp
are baked into every binary via `-ldflags` (see `Makefile`'s `LDFLAGS` and
`internal/version`) — `ai-surface version` (and `GET /health`'s `version`
field) report the running build's exact version/commit/build date. Bump
`VERSION` following semver: patch for fixes, minor for additive
functionality (a new phase), major for a breaking change to CLI
behavior, configuration shape, or the database schema's meaning.
