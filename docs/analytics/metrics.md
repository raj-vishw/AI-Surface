# Analytics Metrics Reference

Every metric below is computed by `internal/repository/analytics` (raw
SQL aggregates over Phase 2-13's own tables) and assembled by
`internal/analytics` (time-range validation, caching). Nothing here
introduces a second copy of any underlying data — every number is a
`COUNT`/`GROUP BY`/`date_trunc` view over rows those phases already
write.

## Time semantics

Unless documented otherwise below, "X over time" and "X by Y within a
range" use the row's own `created_at` — when this platform first
persisted the record, not necessarily when the underlying activity
occurred. Two exceptions, called out explicitly because they use a more
meaningful timestamp:

- **Risk trend** buckets by `risk_scores.calculated_at`.
- **Attack-surface new-assets** buckets by `assets.first_seen`.
- **Investigations closed** buckets by `investigations.closed_at`.

All timestamps are stored and compared in UTC (phase14.md §21); a
caller's local-timezone display, if any, is a presentation-only
conversion never applied before a query.

## Time ranges and intervals

Four presets: `24h`, `7d`, `30d`, `90d`, or an explicit `[start, end)`
pair — always resolved to explicit timestamps before any query runs
(`internal/analytics.ResolveRange`). An explicit range wider than 90
days is rejected (`MaxQueryWindow`). Interval auto-selection:

| Range  | Interval |
| ------ | -------- |
| 24h    | hour     |
| 7d     | day      |
| 30d    | day      |
| 90d    | week     |

An explicit `--interval` always overrides the preset's default.

## Overview (`ai-surface analytics overview`)

Headline counts: total/monitored assets, open findings, open alerts,
active investigations, critical/high risk assets (from each asset's most
recent `risk_scores` row), open correlations, intelligence record count.
Unfiltered, current-state — not time-ranged.

## Risk (`ai-surface analytics risk`)

- **Trend**: per-bucket average/max score and critical/high count from
  `risk_scores`, grouped by `date_trunc(interval, calculated_at)`.
- **Distribution**: severity buckets among each entity's single most
  recent score (a `DISTINCT ON (entity_type, entity_id) ... ORDER BY
  calculated_at DESC` — the same "most recent wins" rule
  `RiskRepository.GetLatestRiskScore` already uses).

## Security Posture (`ai-surface analytics posture`)

**Calculation**: `Score = 100 - average(latest risk score per scored
entity)`. Phase 10's `risk_scores.score` is 0-100 where higher means
riskier; inverting it is a display convention only — no new risk
computation happens here.

**Inputs**: the most recent `risk_scores` row for every entity (asset,
finding, investigation) this target has ever scored.

**Weighting**: none beyond a simple average — Phase 10's own
`AssetCriticality` weighting is already folded into each individual risk
score, so a second weighting here would double-apply it.

**Limitations**: not an objective measure of security (phase14.md §5).
An unscored entity contributes nothing, so sparse data can show a
misleadingly high score — always read `ScoredEntities` alongside `Score`.
A target with zero scored entities reports `Score = 0`, not a fabricated
perfect 100.

## Alerts (`ai-surface analytics alerts`)

Over time, by severity, by status (`open`/`acknowledged`/
`investigating`/`resolved`/`suppressed` — this platform's actual
`rule.AlertStatus` vocabulary), by rule (joined through
`detection_matches` → `rules`).

## Detections (`ai-surface analytics detections`)

- **Matches over time / by rule / by severity**: straightforward
  aggregates over `detection_matches`.
- **Enabled/disabled rules**: counted from `rules.status`.
- **Match rate / alert conversion / dismissal rate** (per rule,
  `RuleRate`): `AlertConversion = Alerts / Matches`,
  `DismissalRate = Dismissed / Alerts` (`Dismissed` counts alerts with
  status `suppressed` — the closest analyst-dismissal-equivalent this
  platform's alert model has). **Never labeled a false-positive rate** —
  this platform has no ground-truth confirmation of which matches were
  genuinely benign (phase14.md §8's own instruction).

## Findings (`ai-surface analytics findings`)

By severity, by category, over time, open-vs-resolved counts, and the
top 10 assets by finding count in range.

## Assets / Attack Surface (`ai-surface analytics assets` /
`attack-surface`)

Total count, by type, by status, critical/high risk counts. Attack
surface trend reuses Phase 2's own `first_seen`/`status` tracking — no
new snapshot table (phase14.md §75): "new assets" buckets `first_seen`
within range; "removed" counts assets with status `inactive`/`retired`
whose `updated_at` falls within range.

## Correlations / Attack Chains (`ai-surface analytics correlations` /
`attack-chains`)

Over time, by severity, by confidence, by status (correlations only —
`open`/`investigating`/`confirmed`/`resolved`/`dismissed`), by strategy
(distinct `correlation_edges.strategy_id` per correlation). Attack-chain
"common stages" groups `attack_chain_stages.stage` by count. **An attack
chain is never presented as a confirmed attack** — see
`docs/investigation/attack-chains.md`.

## Investigations (`ai-surface analytics investigations`)

Serves both "investigation analytics" and "incident analytics"
(phase14.md §14/§15): this platform consolidates Incident into
Investigation (Phase 9's own design, reused unchanged through Phase 11-
13) — there is no second, parallel incidents table to aggregate.

**Mean investigation duration**: `avg(extract(epoch from (closed_at -
created_at)))` over investigations closed within the requested range —
reported in seconds, rendered as a Go `time.Duration` by the CLI. Only
investigations that have actually closed within the range are included;
an investigation still open contributes nothing (never estimated from a
still-ticking clock).

## Threat Intelligence (`ai-surface analytics intelligence`)

By indicator type, by provider (`source_type`/`provider_id` already
distinguishes Phase 10's "local" observations from an external
provider's — this layer surfaces that existing distinction directly
rather than inventing a second internal/external label), by confidence,
and a count of expired records (`expiration < now()`).

## AI Usage (`ai-surface analytics ai`)

Phase 13 operational metrics only: requests over time, by task type, by
provider, average latency, token totals, tool calls by tool, and
**failures** — a request row with no matching response (Phase 13 only
ever inserts a response after a successful `Assistant.Run`, so an
orphaned request is exactly a failed one). **No prompt or response
content is ever included** (phase14.md §17) — only counts and already-
safe identifiers (task type, provider, tool name).

## Analytics versioning

These metric definitions are version 1 (`analytics_version: 1`,
implicit — no metric here has yet had a breaking definition change).
Should a formula above ever change, this document's own git history is
the version record, and the CLI output will note the change at that
time; no numeric version is stamped on individual results yet, since
none has ever needed one.
