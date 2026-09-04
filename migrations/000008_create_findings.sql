-- Phase 8: security findings, mirroring the fingerprints/fingerprint_evidence
-- duality (000006) plus a third append-only table for lifecycle events — see
-- internal/domain/finding and docs/architecture/finding-detection.md.
--
-- findings is "current state": one row per (target_id, asset_id,
-- endpoint_id?, detector_id) identity (see
-- internal/domain/finding.IdentityKey), upserted like fingerprints —
-- FirstSeen is preserved, LastSeen advances, and a finding whose condition
-- is no longer observed in the most recent detection run moves to status
-- 'resolved' rather than being deleted (phase8.md §4 — "do not delete
-- historical findings").
--
-- finding_evidence is the append-only historical trail: one immutable row
-- per distinct evidence snapshot ever observed for a finding, the same
-- role asset_evidence/fingerprint_evidence play for their entities.
--
-- finding_events is the append-only lifecycle audit trail (phase8.md §71):
-- every opened/resolved/reopened/accepted_risk/false_positive/
-- severity-overridden transition, in order, independent of the current-
-- state findings row.
--
-- ON DELETE CASCADE (findings -> assets, finding_evidence -> findings,
-- finding_events -> findings) mirrors fingerprints' own justification
-- (000006): all are dependent child rows that cannot exist without their
-- parent; assets themselves are never hard-deleted in normal operation.
CREATE TABLE IF NOT EXISTS findings (
	id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id                 UUID NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
	asset_id                  UUID NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
	endpoint_id               UUID REFERENCES endpoints (id) ON DELETE CASCADE,
	scan_id                   UUID,
	detector_id               TEXT NOT NULL,
	detector_version          INTEGER NOT NULL DEFAULT 1,
	title                     TEXT NOT NULL,
	description               TEXT NOT NULL DEFAULT '',
	category                  TEXT NOT NULL,
	scope                     TEXT NOT NULL,
	severity                  TEXT NOT NULL,
	detector_severity         TEXT NOT NULL,
	confidence                DOUBLE PRECISION NOT NULL DEFAULT 0,
	status                    TEXT NOT NULL DEFAULT 'open',
	identity_key              TEXT NOT NULL,
	remediation               TEXT NOT NULL DEFAULT '',
	"references"              JSONB NOT NULL DEFAULT '[]'::jsonb,
	metadata                  JSONB NOT NULL DEFAULT '{}'::jsonb,
	severity_overridden       BOOLEAN NOT NULL DEFAULT false,
	severity_override_reason  TEXT NOT NULL DEFAULT '',
	severity_overridden_at    TIMESTAMPTZ,
	suppression_reason        TEXT NOT NULL DEFAULT '',
	first_seen                TIMESTAMPTZ NOT NULL,
	last_seen                 TIMESTAMPTZ NOT NULL,
	resolved_at               TIMESTAMPTZ,
	created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT findings_category_check CHECK (category IN (
		'configuration', 'authentication', 'authorization', 'cryptography',
		'information_disclosure', 'exposure', 'api', 'web', 'infrastructure',
		'technology', 'certificate', 'security_headers'
	)),
	CONSTRAINT findings_scope_check CHECK (scope IN ('asset', 'endpoint', 'target')),
	CONSTRAINT findings_severity_check CHECK (severity IN ('informational', 'low', 'medium', 'high', 'critical')),
	CONSTRAINT findings_detector_severity_check CHECK (detector_severity IN ('informational', 'low', 'medium', 'high', 'critical')),
	CONSTRAINT findings_status_check CHECK (status IN ('open', 'resolved', 'reopened', 'accepted_risk', 'false_positive')),
	CONSTRAINT findings_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
	CONSTRAINT findings_detector_id_not_blank CHECK (btrim(detector_id) <> ''),
	CONSTRAINT findings_title_not_blank CHECK (btrim(title) <> ''),
	CONSTRAINT findings_identity_key_not_blank CHECK (btrim(identity_key) <> ''),
	CONSTRAINT findings_endpoint_scope_consistency CHECK (
		(scope = 'endpoint' AND endpoint_id IS NOT NULL) OR
		(scope <> 'endpoint' AND endpoint_id IS NULL)
	),
	CONSTRAINT findings_suppression_reason_required CHECK (
		status NOT IN ('accepted_risk', 'false_positive') OR btrim(suppression_reason) <> ''
	)
);

-- The deduplication/upsert boundary: one identity_key (target + asset +
-- endpoint? + detector, see internal/domain/finding.IdentityKey) is always
-- exactly one row, regardless of how many detection runs observe it — see
-- internal/repository/finding.Upsert's single atomic ON CONFLICT statement.
CREATE UNIQUE INDEX IF NOT EXISTS findings_identity_key_unique ON findings (identity_key);

-- Lookup patterns (phase8.md §16/§70): every finding for a target/asset/
-- endpoint (most common), filtering/reporting by detector, severity,
-- status, scan, and recency.
CREATE INDEX IF NOT EXISTS findings_target_id_idx ON findings (target_id);
CREATE INDEX IF NOT EXISTS findings_asset_id_idx ON findings (asset_id);
CREATE INDEX IF NOT EXISTS findings_endpoint_id_idx ON findings (endpoint_id);
CREATE INDEX IF NOT EXISTS findings_scan_id_idx ON findings (scan_id);
CREATE INDEX IF NOT EXISTS findings_detector_id_idx ON findings (detector_id);
CREATE INDEX IF NOT EXISTS findings_severity_idx ON findings (severity);
CREATE INDEX IF NOT EXISTS findings_status_idx ON findings (status);
CREATE INDEX IF NOT EXISTS findings_first_seen_idx ON findings (first_seen);
CREATE INDEX IF NOT EXISTS findings_last_seen_idx ON findings (last_seen);

-- Append-only evidence backing a finding (mirrors fingerprint_evidence,
-- 000006, exactly) — a row here is never updated or deleted; a changed/
-- newly-corroborating observation is always a new row.
CREATE TABLE IF NOT EXISTS finding_evidence (
	id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	finding_id            UUID NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
	source                TEXT NOT NULL,
	evidence_type         TEXT NOT NULL,
	evidence_data         JSONB NOT NULL DEFAULT '{}'::jsonb,
	evidence_fingerprint  CHAR(64) NOT NULL,
	confidence            DOUBLE PRECISION NOT NULL DEFAULT 0,
	observed_at           TIMESTAMPTZ NOT NULL,
	created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT finding_evidence_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
	CONSTRAINT finding_evidence_source_not_blank CHECK (btrim(source) <> '')
);

-- Deduplication boundary: an unchanged evidence snapshot is stored once per
-- (finding, source), not once per detection run.
CREATE UNIQUE INDEX IF NOT EXISTS finding_evidence_dedup_unique
	ON finding_evidence (finding_id, source, evidence_fingerprint);

CREATE INDEX IF NOT EXISTS finding_evidence_finding_id_idx ON finding_evidence (finding_id);
CREATE INDEX IF NOT EXISTS finding_evidence_observed_at_idx ON finding_evidence (observed_at);

-- Append-only lifecycle audit trail (phase8.md §71/§85) — independent of
-- the current-state findings row; never updated or deleted.
CREATE TABLE IF NOT EXISTS finding_events (
	id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	finding_id   UUID NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
	scan_id      UUID,
	event_type   TEXT NOT NULL,
	from_status  TEXT NOT NULL DEFAULT '',
	to_status    TEXT NOT NULL DEFAULT '',
	severity     TEXT NOT NULL DEFAULT '',
	confidence   DOUBLE PRECISION NOT NULL DEFAULT 0,
	reason       TEXT NOT NULL DEFAULT '',
	detected_at  TIMESTAMPTZ NOT NULL,
	created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT finding_events_type_check CHECK (event_type IN (
		'finding_opened', 'finding_updated', 'finding_resolved', 'finding_reopened',
		'finding_accepted', 'finding_marked_false_positive', 'finding_severity_overridden'
	)),
	CONSTRAINT finding_events_confidence_range CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE INDEX IF NOT EXISTS finding_events_finding_id_idx ON finding_events (finding_id);
CREATE INDEX IF NOT EXISTS finding_events_detected_at_idx ON finding_events (detected_at);
