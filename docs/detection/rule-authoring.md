# Detection Rule Authoring Guide

Rules are authored as JSON or YAML and validated/compiled before they
can ever be evaluated. See
[docs/architecture/detection-engine.md](../architecture/detection-engine.md)
for the full architecture, and
[docs/detection/builtin-rules.md](builtin-rules.md) for 5 complete,
working examples.

## Fields available per event type

Every rule references normalized fields, namespaced by source
(`internal/ruleengine.DefaultSchema`) — never a raw log field, since this
platform has no raw-log-ingestion pipeline:

| Event type | Fields |
| --- | --- |
| `finding` | `finding.severity`, `finding.confidence`, `finding.category`, `finding.status`, `finding.detector_id`, `finding.scope` |
| `asset_observation` | `asset.type`, `asset.status`, `asset.confidence`, `asset.hostname`, `asset.ip`, `asset.source` |
| `endpoint_observation` | `endpoint.classification`, `endpoint.confidence`, `endpoint.method`, `endpoint.status` |
| `fingerprint_change` | `fingerprint.technology`, `fingerprint.category`, `fingerprint.confidence`, `fingerprint.status` |
| `intelligence_record` | `intelligence.verdict`, `intelligence.confidence`, `intelligence.category`, `intelligence.source_type`, `intelligence.indicator_type` |

Every event type also carries `event.timestamp`, `event.target_id`,
`event.asset_id`. Referencing a field outside this table is a validation
error (`rule.validation.invalid_field`) — never silently treated as
absent.

## A basic field_match rule

Fires once per matching event, no grouping or window:

```yaml
name: critical_exposure_finding
event_type: finding
rule_type: field_match
severity: critical
confidence: high
schema_version: 1
conditions:
  - field: finding.category
    operator: equals
    value: exposure
  - field: finding.severity
    operator: equals
    value: critical
  - field: finding.status
    operator: equals
    value: open
```

## A threshold rule

```yaml
name: high_severity_finding_burst
event_type: finding
rule_type: threshold
severity: high
confidence: medium
schema_version: 1
conditions:
  - field: finding.severity
    operator: in
    value: [high, critical]
  - field: finding.status
    operator: equals
    value: open
aggregation:
  group_by:
    - event.asset_id
  window:
    duration: 1h
  threshold:
    operator: greater_than_or_equal
    value: 3
```

## An aggregation rule (unique_count)

```yaml
name: technology_change_spike
event_type: fingerprint_change
rule_type: aggregation
severity: low
confidence: medium
schema_version: 1
aggregation:
  group_by:
    - event.asset_id
  window:
    duration: 10m
  function: unique_count
  unique_field: fingerprint.technology
  threshold:
    operator: greater_than_or_equal
    value: 3
```

## A sequence rule

```yaml
name: new_finding_after_asset_change
event_type: finding
rule_type: sequence
severity: medium
confidence: low
schema_version: 1
sequence:
  group_by:
    - event.asset_id
  window:
    duration: 24h
  steps:
    - event_type: asset_observation
    - event_type: finding
      conditions:
        - field: finding.severity
          operator: in
          value: [high, critical]
```

## A negative example (what NOT to do)

```yaml
# INVALID — rejected at validation time:
conditions:
  - field: finding.confidence      # a float field
    operator: greater_than_or_equal
    value: "very high"             # not a number — rule.validation.type_mismatch
  - field: finding.mispelled_field # unknown field — rule.validation.invalid_field
```

## False-positive guidance

Every rule you author should document its own likely false positives —
see [builtin-rules.md](builtin-rules.md) for the standard this platform
holds itself to. A rule with no documented false-positive
considerations is a rule an analyst can't triage confidently.

## Testing workflow

```sh
# Validate + compile without touching the database at all:
ai-surface detection builtin test <name>          # for a built-in rule

# For a rule you're authoring, write test fixtures as Go
# ruleengine.TestCase values (see internal/ruleengine/builtin/builtin.go
# for worked examples) and call ruleengine.RunTest directly, or persist
# the rule as draft and use `ai-surface detection evaluate <id> --dry-run`
# against real historical data without creating any alert.
```

## Deployment workflow

```sh
# 1. Create as draft.
ai-surface detection create --target example.com --name my_rule \
  --definition-file my_rule.yaml --created-by analyst1

# 2. Dry-run it against recent history.
ai-surface detection evaluate <rule-id> --dry-run --from 2026-01-01T00:00:00Z --to 2026-01-02T00:00:00Z

# 3. Enable it once you're satisfied.
ai-surface detection enable <rule-id> --actor analyst1

# 4. Evaluate for real (creates matches/alerts).
ai-surface detection evaluate <rule-id> --from ... --to ...

# 5. Edit later by creating a new version — the old version, and every
#    match it ever produced, remain untouched and reproducible.
ai-surface detection edit <rule-id> --definition-file my_rule_v2.yaml \
  --change-description "tightened threshold" --created-by analyst1
```
