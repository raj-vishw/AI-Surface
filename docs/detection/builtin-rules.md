# Built-in Detection Rules

Five built-in rules ship with Phase 11 (`internal/ruleengine/builtin`),
one per supported rule type plus a second threshold example. Every rule
operates ONLY on this platform's own already-normalized findings/asset/
fingerprint/intelligence data — none claims to detect a specific
real-world threat actor. List them with `ai-recon detection builtin
list`; run a rule's own regression suite with `ai-recon detection
builtin test <name>`; persist one for a target with `ai-recon detection
builtin install <name> --target <t> --created-by <analyst>`.

## high_severity_finding_burst

**Type**: threshold · **Severity**: high · **Confidence**: medium

**Purpose**: Surface an asset whose finding history is accumulating
high-severity conditions rapidly — often a sign of a genuinely
deteriorating security posture, or a detector/scan misconfiguration
worth reviewing.

**Logic**: Groups findings by asset; fires when 3+ findings with
severity in `{high, critical}` are observed for the same asset within a
1-hour window.

**Expected inputs**: `finding` events with `finding.severity` and
`finding.status`.

**Limitations**: Counts findings regardless of detector — a single
noisy detector re-firing across several scans can trigger this as
easily as three genuinely distinct conditions.

**False positives**:
- A single misbehaving detector producing several near-duplicate
  high-severity findings in one scan run.
- A newly-onboarded asset receiving its first full scan, surfacing
  several pre-existing conditions at once.

**Test coverage**: positive (3 findings within the window), negative (2
findings, below threshold), boundary (exactly 3 at the threshold).

## new_finding_after_asset_change

**Type**: sequence · **Severity**: medium · **Confidence**: low

**Purpose**: Surface a plausible temporal link between an asset's own
attack surface changing and a new significant finding appearing shortly
after — worth an analyst's attention even though this rule cannot
establish causation on its own.

**Logic**: Sequence: an `asset_observation` event, followed by a
`finding` event with severity in `{high, critical}` on the SAME asset,
within a 24-hour window.

**Expected inputs**: `asset_observation` and `finding` events sharing
`event.asset_id`.

**Limitations**: This is a temporal correlation, not a causal one — an
unrelated finding surfacing shortly after routine re-scanning is common
and expected.

**False positives**:
- Routine periodic re-scanning naturally re-observes an asset
  immediately before its next scheduled detection pass.
- Two unrelated changes happening to land within the same 24-hour
  window by coincidence.

**Test coverage**: positive (correct order within window), negative
(wrong order), boundary (just inside the 24h window).

## repeated_malicious_intelligence_signal

**Type**: threshold · **Severity**: high · **Confidence**: medium

**Purpose**: A single provider's malicious verdict is deliberately never
treated as confirmed (see `docs/security/risk-model-v1.md` and Phase
10's own aggregation logic); repeated malicious signals across separate
lookups raise that context's weight enough to warrant analyst review,
without this rule itself claiming confirmation.

**Logic**: Groups Phase 10 intelligence records by asset; fires when 2+
records with `intelligence.verdict = malicious` are observed for the
same asset within a 1-hour window.

**Expected inputs**: `intelligence_record` events with
`intelligence.verdict`.

**Limitations**: Does not distinguish which provider(s) reported
malicious — see the underlying `intelligence_records` rows for full
provenance before acting.

**False positives**:
- An intelligence provider re-confirming the same finding across a
  scheduled refresh, counted as if it were an independent signal.
- A provider's own false-positive rate for the indicator category
  involved.

**Test coverage**: positive (2 malicious within the window), negative (1
malicious + 1 benign), boundary (exactly 2 at the threshold).

## technology_change_spike

**Type**: aggregation (`unique_count`) · **Severity**: low ·
**Confidence**: medium

**Purpose**: A sudden burst of distinct technology fingerprints on one
asset often indicates a significant, worth-reviewing infrastructure
change (a migration, a new deployment, or a misconfigured/rotating
proxy).

**Logic**: Groups Phase 6 fingerprint-change events by asset; fires when
3+ DISTINCT `fingerprint.technology` values are observed for the same
asset within a 10-minute window.

**Expected inputs**: `fingerprint_change` events with
`fingerprint.technology`.

**Limitations**: A single re-scan that simply re-confirms several
already-known technologies at once can also trigger this if those
technologies were only just fingerprinted for the first time in this
run.

**False positives**:
- The very first fingerprinting pass against a newly-onboarded asset,
  which legitimately identifies several technologies at once.
- A load balancer or CDN fronting several distinct backend technologies
  simultaneously.

**Test coverage**: positive (3 distinct technologies), negative (same
technology repeated 3 times), boundary (exactly 3 distinct).

## critical_exposure_finding

**Type**: field_match · **Severity**: critical · **Confidence**: high

**Purpose**: Immediately surface the single most severe, highest-
priority class of finding this platform already detects (Phase 8's
exposure/information-disclosure detectors), without waiting for any
aggregation window.

**Logic**: A single `finding` event with `finding.category = exposure`
AND `finding.severity = critical` AND `finding.status = open` is itself
the match — no grouping or window involved.

**Expected inputs**: `finding` events with `finding.category`,
`finding.severity`, `finding.status`.

**Limitations**: Entirely dependent on Phase 8's own detectors correctly
classifying category/severity — this rule adds no additional evidence
beyond what the finding itself already carries.

**False positives**:
- An accepted-risk condition that hasn't yet been marked
  `accepted_risk`/`false_positive` in Phase 8.

**Test coverage**: positive (critical + open), negative (high, not
critical), boundary (critical but already resolved).
