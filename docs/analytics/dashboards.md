# Dashboards

This platform has no frontend anywhere in its codebase (confirmed by
inspection before Phase 14 began — only `/health`/`/ready` exist as HTTP
endpoints). Every "dashboard" phase14.md asks for is therefore adapted to
its CLI-only precedent, exactly as every prior phase adapted its own
missing infrastructure: a dashboard is `ai-surface analytics <command>`'s
tabwriter-formatted output, and a "preset" is simply which handful of
`analytics`/`report` subcommands an analyst runs together.

## Dashboard types and their commands

| Dashboard (phase14.md name) | Commands |
| --- | --- |
| Executive | `analytics overview`, `analytics posture`, `analytics risk`, `report create --type executive` |
| SOC | `analytics overview`, `analytics alerts`, `analytics correlations`, `analytics investigations`, `analytics detections` |
| Attack Surface | `analytics attack-surface`, `analytics assets`, `report create --type attack_surface` |
| Investigation | `report create --type investigation --subject <id>` (pulls summary/severity/alerts/findings/correlations/attack-chain/timeline/assets/intelligence in one report) |
| Incident | Same as Investigation — see `docs/analytics/metrics.md`'s note on the Phase 9 consolidation |
| Detection Engineering | `analytics detections`, `report create --type detection` |
| Threat Intelligence | `analytics intelligence` |

## Filters

Every `analytics`/`report` command that operates on one target's data
accepts `--target`/`--target-type` — this platform's authorization
boundary (see "Authorization" below). Time-ranged commands additionally
accept `--range` (24h/7d/30d/90d) or explicit `--from`/`--to`, and
`--interval` to override the auto-selected bucket size. Only the filters
this platform's actual data model supports are exposed (phase14.md §22)
— there is no severity/status/asset-type filter on every single command,
only where the underlying query already groups by that dimension (see
`docs/analytics/metrics.md` for exactly which breakdowns each command
provides).

## Filter persistence

`dashboard_preferences` (migration `000014_create_reporting.sql`) is a
minimal, generic, user+target-scoped named-filter-set table — the
smallest structure that satisfies phase14.md §23's "analysts can save
dashboard filters" given this platform has no broader user-preference
system to extend. No CLI surface reads/writes it yet in this phase (a
documented Known Limitation) — the table exists so a future phase can
add `--save-as <name>`/`--load <name>` without a schema migration.

## Drill-down

Every aggregate this layer returns names the underlying entity type
(rule name, asset identity, correlation id, ...) needed to look it up
directly with an existing command — e.g. `analytics alerts`'s "By Rule"
breakdown names a rule you can then inspect with `ai-surface detection show
<rule-id>` (Phase 11), and `analytics correlations`'s counts point at
correlations inspectable with `ai-surface correlation show <id>` (Phase
12). There is no separate "click to filter" mechanic to implement in a
CLI — the drill-down *is* running the next command with that id.

## Caching

`internal/analytics.Cache` is a bounded-TTL (default 30s), in-process
cache keyed by `(target, metric, range, filters-hash)` — never
authoritative (a cache miss always falls through to a real query, so a
restarted process never serves stale data) and never crossing a target
boundary (see `internal/analytics/cache_test.go`'s
`TestCache_ExpiresAfterTTL` / `TestService_Overview_CachesPerTarget`).
This is process-local, not cluster-wide — this platform has no shared
cache/queue infrastructure in active use (Redis is verified at startup
only), a documented adaptation matching Phase 13's own rate limiter.

## Empty / loading / error states

A CLI command has no separate "loading" state (the process blocks until
the query returns, or errors); "empty" is handled per-command — every
breakdown/time-series prints an explicit `(none)` / `(no data in range)`
line rather than a misleading blank table. Errors surface as a plain,
human-readable message on stderr (cobra's `RunE` convention) — never a
raw SQL string, stack trace, or connection string (the same
`ClientMessage()`/database-category-never-leaks-detail discipline
`internal/errors` already enforces platform-wide).

## Accessibility / responsiveness

Not applicable to a CLI — there is no visual rendering surface for
contrast, keyboard navigation, or viewport width to apply to. Tabular
`tabwriter` output is inherently screen-reader-compatible plain text.
