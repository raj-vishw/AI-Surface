# Attack Chains

An `AttackChain` (`internal/domain/correlation/chain.go`) is a narrative
summary of one `Correlation`'s graph as an ordered sequence of generic
stages. **It is not automatic proof of an attack** — it is a
representation of correlated activity an analyst must review, exactly
like its parent `Correlation`.

## Model

```
Correlation (1) ── (0..1) AttackChain ── (0..n) AttackChainStage
```

A chain is created only when at least one node in its correlation's graph
classifies into a recognized stage (see below) — a correlation with no
classifiable evidence simply has no chain at all; nothing is invented to
fill one in.

`AttackChain` fields: `Name`, `Description`, `Confidence` (three-level,
matching its parent `Correlation`), `Severity` (mirrors the parent), and
`Status` (`open/investigating/confirmed/resolved/dismissed` — the same
vocabulary, so a chain's lifecycle tracks its correlation's).

## Stages

Nine generic, non-ATT&CK-mapped stages:

```
initial_activity     authentication      execution
privilege_change     persistence_signal  discovery_signal
network_activity     data_access         impact_signal
```

Deliberately generic: this platform makes no claim to map onto a formal
kill-chain or MITRE ATT&CK technique — the stage names describe the kind
of signal observed, not a confirmed technique.

## Classification (how a node becomes a stage)

`internal/correlation/chain.go`'s `classifyStage` is a documented,
best-effort heuristic — never a claim that the underlying evidence proves
a technique occurred:

- An authentication-category finding/detection → `authentication`.
- An intelligence record with verdict `malicious`/`suspicious` →
  `network_activity`.
- An asset observation → `initial_activity` (a newly-observed asset is
  the earliest activity signal available).
- An endpoint observation, or an exposure/information-disclosure
  finding → `discovery_signal`.
- A detection match: its rule's `Category` is matched by keyword
  (`privilege` → `privilege_change`, `persistence` → `persistence_signal`,
  `discovery` → `discovery_signal`, `exfil`/`data` → `data_access`,
  `impact`/`destruct` → `impact_signal`, anything else with a category →
  `execution` as a conservative default, empty category → unclassified).
- Anything else → unclassified (contributes to the correlation's
  evidence, but not to the chain).

## Stage evidence

Every persisted `AttackChainStage` carries at least one
`StageEvidenceRef{NodeType, ReferenceID}` — validation rejects a stage
with none (`AttackChainStage.Validate`). Evidence is stored as a small
JSON array on the stage row rather than a seventh table, the same
"opaque JSON for a small, never-independently-queried structure" choice
`rule_versions.definition` makes for Phase 11's own `Definition`.

## Stage confidence and chain confidence

Each stage's own `Confidence` is the highest confidence among the edges
touching its evidence nodes (or `low` for an isolated node with no
edges). A chain's overall `Confidence` is **not** a bare average of its
stages — it's an evidence-weighted combination
(`internal/correlation/chain.go`'s `chainConfidence`): a stage backed by
five pieces of evidence influences the result more than one backed by a
single node, and the weighted mean is rounded (not truncated), so a
mean of 1.6 rounds up to `high` rather than down to `medium`.

## Gaps

If a chain has evidence for `authentication` and `privilege_change` but
nothing for `execution`, the chain simply has two stages, not three —
`execution` is an observed gap, never fabricated to make the narrative
feel complete. `ai-recon chain show`/`explain` render exactly the stages
that exist; there is no "unknown" placeholder stage inserted between
them (a genuine `unknown`/gap presentation is a documented product
choice left for a future phase, per phase12.md §44's either/or wording).

## Analyst confirmation and dismissal

A chain's `Status` follows its correlation's: `ai-recon correlation
confirm <id>` requires an actor (and accepts optional notes); `ai-recon
correlation dismiss <id>` requires a reason. Neither the engine nor the
service layer ever transitions a chain to `confirmed` on its own —
`internal/correlation` produces language like "correlated activity" and
"suspicious activity chain," never "confirmed attack."

## CLI

```sh
ai-recon chain list                 # every attack chain
ai-recon chain show <id>            # stages, confidence, severity, status
ai-recon chain explain <id>         # + the parent correlation's own explanation text
```

## Limitations

- Stage classification is a heuristic over existing category/rule-category
  labels, not a formal technique-detection engine.
- One chain per correlation (no branching/parallel sub-chains).
- A chain never spans more than one correlation's graph; merging two
  correlations (`ai-recon correlation merge`) does not currently
  recompute or merge their chains — each retains its own until the next
  evaluation regenerates one for the merged evidence set.
