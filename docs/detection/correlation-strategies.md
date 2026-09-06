# Correlation Strategy Guide

Six built-in strategies ship with Phase 12
(`internal/correlation/strategies`), each independently testable and
registered into an `internal/correlation.StrategyRegistry`. List them
programmatically via `StrategyRegistry.Metadata()`; every one below is
enabled by default and can be disabled per-evaluation via
`Config.Strategies`.

## asset

**Purpose**: Link observations that already reference the same asset —
this platform's strongest, directly-**observed** signal.

**Inputs**: Any observation with a non-nil `AssetID`.

**Matching logic**: Two observations with the same `AssetID` and
different `(Type, ReferenceID)` identity.

**Confidence**: High. **Provenance**: Observed.

**False positives**: None from the signal itself — it restates an
already-recorded relationship. The risk is over-weighting it: many
findings on a busy asset is expected, not necessarily meaningful on its
own.

**Limitations**: Says nothing about *why* two observations are related
beyond sharing an asset — see other strategies for more specific signals.

**Example**: A finding and a detection match both reference asset
`a1b2...`. Edge: `observed_on`, confidence `high`, evidence "Both
observations reference asset a1b2... directly — an already-recorded
relationship, not an inference."

## temporal

**Purpose**: Link observations that occurred close together in time —
phase12.md's own explicit warning that this is a "weak, standalone
signal" is honored: `ConfidenceLow`, always `inferred`.

**Inputs**: Any two observations, any type.

**Matching logic**: Sorted by timestamp, then a sliding window — two
observations are linked when their gap is within
`Config.EffectiveTemporalWindow()` (default 15m, max 24h).

**Confidence**: Low. **Provenance**: Inferred.

**False positives**: Two unrelated observations landing in the same
window purely by coincidence — routine scanning activity, scheduled
re-checks, or simply a busy target with many findings.

**Limitations**: Never claims causation, only proximity. This strategy
alone should never be the sole basis for escalation.

**Example**: A finding at 10:00 and an asset observation at 10:03,
window 15m → edge `followed_by`, confidence `low`.

## identity

**Purpose**: This platform's adaptation of "identity correlation" —
ai-recon has no user/session/login model, so there is no failed-login →
successful-login sequence to correlate by username. Instead, this links
authentication-**category** findings/detections on the same asset — the
closest honest analog available.

**Inputs**: Observations with `Category == "authentication"` and a
non-nil `AssetID`.

**Matching logic**: Two authentication-category observations sharing an
asset.

**Confidence**: Low. **Provenance**: Inferred.

**False positives**: Multiple authentication-surface findings on one
asset from unrelated causes (a weak-cipher TLS finding and a missing
rate-limit finding, say) — co-location is not compromise.

**Limitations**: Never assumes two observations are related because
identifiers "look similar" — there is no identifier comparison at all,
only asset co-location.

## network

**Purpose**: Link observations whose assets share an IP address — uses
Phase 2's already-recorded `Asset.IP`, never a new network scan.

**Inputs**: Observations with a non-empty `IP`.

**Matching logic**: Same IP, **different** `AssetID` (same-asset sharing
is `asset`'s stronger, observed signal — this strategy explicitly skips
it to avoid double-counting).

**Confidence**: Low. **Provenance**: Inferred.

**False positives**: Shared infrastructure — a CDN, a load balancer, or
shared hosting — can host many unrelated systems behind one IP. This is
explicitly called out in every edge's own evidence text.

**Limitations**: IPv4/IPv6 both supported (string comparison); no
attempt to resolve CIDR-adjacency or ASN ownership.

## detection

**Purpose**: Link two **different** Phase 11 detection rules that both
fired on the same asset, in chronological order — phase12.md's worked
example (repeated auth failures → successful login → privilege change).

**Inputs**: `NodeDetectionMatch` observations with a resolved `AssetID`
(resolved via the match's own evidence — see the architecture doc's
"Evidence / graph model" section) and `RuleID`.

**Matching logic**: For each asset, matches sorted chronologically;
edges only between matches from **different** rules (same-rule repeats
are that rule's own deduplication concern, not a cross-rule sequence).

**Confidence**: Medium. **Provenance**: Inferred.

**False positives**: Two independently-firing rules that happen to touch
the same asset in sequence without any real relationship — busy assets
with many enabled rules see this most often.

**Limitations**: Each underlying `DetectionMatch` is preserved
independently; this strategy never merges, replaces, or re-scores a
match — it only adds an edge between two already-explained rows.

## intelligence

**Purpose**: Link an asset (or anything observed on it) to a Phase 10
intelligence record whose indicator value matches the asset's IP or
hostname — always labeled EXTERNAL, never presented as this platform's
own observed activity (phase10.md's identical discipline for `Verdict`).

**Inputs**: `NodeIntelligenceRecord` observations (`IndicatorValue`,
`Verdict`, `Confidence`) and any observation with a non-empty `IP` or
`Hostname`.

**Matching logic**: `Record.IndicatorValue == observation.IP` or
`== observation.Hostname`.

**Confidence**: Mapped from the intelligence record's own reported
confidence (never upgraded past what the provider stated). **Provenance**:
Observed (the indicator match itself is a direct string comparison, not
a guessed pattern).

**False positives**: A provider's own false-positive rate for the
indicator category; a shared IP an intelligence feed flagged for
unrelated infrastructure sharing it.

**Limitations**: Never claims a verdict of "malicious" means confirmed
malicious activity — every edge's evidence text says "a third-party
classification, not activity this platform directly observed."

## Testing

Each strategy has its own unit tests in
`internal/correlation/strategies/strategies_test.go` (boundary inclusion
for `temporal`, same-asset exclusion for `identity`/`network`, observed
high-confidence for `asset`, same-rule exclusion for `detection`,
external labeling for `intelligence`) plus `TestRegisterAll_
RegistersEveryStrategyOnce`.
