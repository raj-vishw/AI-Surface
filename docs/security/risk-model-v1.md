# Risk Model v1

`internal/intelligence/risk.Scorer` (model version `"v1"`,
`risk.ModelVersion`) computes a deterministic, explainable 0-100 risk
score. This document is the reproducible reference for that formula —
every number here matches `risk.DefaultWeights()` exactly.

## Score Range

`0` (lowest) to `100` (highest), always an integer, always clamped —
`Scorer.Calculate` sums every contributing factor's points and clamps the
result to `[0, 100]` regardless of how many factors fire (phase10.md
§42). A score can never be negative even when every applicable factor is
negative (`AssetCriticalityLow` is the only negative weight).

## Severity

The clamped score buckets into a named severity with fixed boundaries
(`risk.SeverityForScore`, identical in
`internal/domain/intelligence.RiskSeverityForScore`):

| Score range | Severity |
| --- | --- |
| 0-24 | `low` |
| 25-49 | `medium` |
| 50-74 | `high` |
| 75-100 | `critical` |

## Factors and Weights

Each factor contributes at most once per calculation (never summed
across every open finding, for example — see Limitations). A factor with
0 points configured, or whose condition doesn't apply, is simply absent
from the result's `Factors` list.

| Factor | Condition | Points |
| --- | --- | --- |
| `finding_severity` | Highest-severity OPEN finding under consideration | critical +40, high +30, medium +18, low +8, informational +2 |
| `finding_confidence` | That finding's own detection confidence is `high`/`very_high` | +4 |
| `internet_exposure` | Asset is an HTTP/API/AI endpoint, or carries a URL | +20 |
| `open_services` | Count of open PORT/SERVICE assets sharing the host | +2 per service, capped at +10 |
| `sensitive_endpoints` | Count of Phase 7 endpoints classified `auth`/`api` | +5 (flat, once) |
| `exposed_api` | Any endpoint classified `api`/`graphql`/`openapi`/`swagger` | +5 |
| `vulnerability_match` | Strongest vulnerability match status | confirmed +20, probable +10 (no_match/insufficient_evidence: 0) |
| `threat_intelligence` | Aggregated intelligence verdict for a related indicator | malicious +15, suspicious +7 (benign/unknown: 0) |
| `asset_criticality` | Analyst-set criticality (`ai-recon risk criticality set`) | critical +15, high +10, normal 0, low -5 |
| `recent_change` | Asset's `updated_at` is within the last 7 days | +10 |

These are the exact values `risk.DefaultWeights()` returns; an operator
may override the complete set via `intelligence.risk.weights` in
configuration (phase10.md §44: weights are documented, and never changed
silently — a customized set must supply every field, the same
all-or-nothing convention `fingerprint.thresholds` already uses).

## Confidence

The model's confidence in its *own* result (not any individual factor's
confidence) is a leveled value derived from how many independent signal
categories actually contributed:

| Contributing signal categories | Confidence |
| --- | --- |
| 2 or more of {finding severity, vulnerability match, intelligence verdict} present | `high` |
| Exactly 1 present | `medium` |
| None present | `low` |

An input with zero contributing factors is reported at `low` confidence
rather than a deceptively precise score with nothing behind it.

## Worked Examples

**Example 1 — phase10.md §41's own worked scenario:**

```
Risk Score: 84

Factors:
    highest open finding severity: high: +30
    high detection confidence on the contributing finding: +4
    asset is internet-facing: +20
    confirmed technology vulnerability match: +20
    asset or technology changed recently: +10
```

30 + 4 + 20 + 20 + 10 = 84 → severity `critical` (≥75).

**Example 2 — no findings, no vulnerabilities, no intelligence signal:**

```
Risk Score: 0 — no contributing risk factors were found in currently available data
```

Severity `low`, confidence `low`.

**Example 3 — every factor firing at once (clamp demonstration):**

Critical finding (+40) + high confidence (+4) + internet-facing (+20) +
50 open services (capped, +10) + sensitive endpoints (+5) + exposed API
(+5) + confirmed vulnerability (+20) + malicious intelligence (+15) +
critical asset criticality (+15) + recent change (+10) sums to 144 —
clamped to **100**, severity `critical`.

## Limitations

- **One finding, not every finding.** The model scores the single
  highest-severity open finding under consideration, not a sum across
  every open finding on an asset — summing would let ten low-severity
  findings outscore one critical finding, which is not the intent.
- **Exposure signals reuse existing classifications.** "Internet-facing"
  is a type/URL-presence heuristic over Phase 2's asset model;
  "sensitive endpoint"/"exposed API" reuse Phase 7's endpoint
  `Classification` field directly. Neither re-derives actual network
  reachability (e.g. firewall rules) — they are honest proxies over
  already-collected evidence, not a network-level reachability probe.
- **Weights are documented point values, not calibrated coefficients.**
  Nothing in this model claims statistical calibration (phase10.md §55);
  a score of 84 does not mean "84% likely to be exploited" — it means
  "this many documented risk factors were present, at these documented
  weights."
- **Risk is not vulnerability confirmation.** A high score never implies
  a `confirmed` vulnerability status on its own — `vulnerability_match`
  only contributes when the underlying `VulnerabilityMatch` itself is
  `confirmed` or `probable` (phase10.md §35).
