-- Phase 11: detection rule engine — see internal/domain/rule and
-- docs/architecture/detection-engine.md.
--
-- rules holds a rule's identity and current metadata only; the
-- versioned, immutable logic lives in rule_versions (phase11.md §4/§5)
-- — a rule is never hard-deleted (status moves to 'deprecated' instead),
-- and a rule_version row is never updated once created (see
-- rule_versions' own comment below).
CREATE TABLE IF NOT EXISTS rules (
	id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id         UUID NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
	name              TEXT NOT NULL,
	description       TEXT NOT NULL DEFAULT '',
	status            TEXT NOT NULL DEFAULT 'draft',
	rule_type         TEXT NOT NULL,
	severity          TEXT NOT NULL,
	confidence        TEXT NOT NULL,
	category          TEXT NOT NULL DEFAULT '',
	tags              TEXT[] NOT NULL DEFAULT '{}',
	"references"      TEXT[] NOT NULL DEFAULT '{}',
	documentation_url TEXT NOT NULL DEFAULT '',
	created_by        TEXT NOT NULL,
	updated_by        TEXT NOT NULL DEFAULT '',
	created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT rules_status_check CHECK (status IN ('draft', 'enabled', 'disabled', 'deprecated')),
	CONSTRAINT rules_rule_type_check CHECK (rule_type IN ('field_match', 'threshold', 'sequence', 'aggregation')),
	CONSTRAINT rules_severity_check CHECK (severity IN ('informational', 'low', 'medium', 'high', 'critical')),
	CONSTRAINT rules_confidence_check CHECK (confidence IN ('very_low', 'low', 'medium', 'high', 'very_high')),
	CONSTRAINT rules_name_not_blank CHECK (btrim(name) <> ''),
	CONSTRAINT rules_created_by_not_blank CHECK (btrim(created_by) <> '')
);

-- A rule's name is its stable, human-addressable identity within a
-- target (phase11.md §3's "suspicious_login_pattern" worked example).
CREATE UNIQUE INDEX IF NOT EXISTS rules_target_name_unique ON rules (target_id, name);
CREATE INDEX IF NOT EXISTS rules_target_id_idx ON rules (target_id);
CREATE INDEX IF NOT EXISTS rules_status_idx ON rules (status);

-- Versioned, immutable rule logic (phase11.md §4/§5) — this table has no
-- UPDATE path anywhere in internal/repository/rule except toggling
-- `enabled`; definition/definition_hash are write-once. A detection
-- result is always traceable to exactly one (rule_id, version) pair.
CREATE TABLE IF NOT EXISTS rule_versions (
	id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	rule_id              UUID NOT NULL REFERENCES rules (id) ON DELETE RESTRICT,
	version              INTEGER NOT NULL,
	definition           JSONB NOT NULL,
	definition_hash      CHAR(64) NOT NULL,
	enabled              BOOLEAN NOT NULL DEFAULT true,
	event_schema_version INTEGER NOT NULL DEFAULT 1,
	created_by           TEXT NOT NULL,
	created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
	change_description   TEXT NOT NULL DEFAULT '',
	CONSTRAINT rule_versions_version_positive CHECK (version >= 1),
	CONSTRAINT rule_versions_created_by_not_blank CHECK (btrim(created_by) <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS rule_versions_rule_version_unique ON rule_versions (rule_id, version);
CREATE INDEX IF NOT EXISTS rule_versions_rule_id_idx ON rule_versions (rule_id);

-- Detection matches (phase11.md §16) — deduplicated by fingerprint
-- (phase11.md §33): re-observing the same underlying pattern within the
-- same normalized window widens last_observed_at rather than creating a
-- duplicate row.
CREATE TABLE IF NOT EXISTS detection_matches (
	id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id         UUID NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
	rule_id           UUID NOT NULL REFERENCES rules (id) ON DELETE RESTRICT,
	rule_version      INTEGER NOT NULL,
	fingerprint       CHAR(64) NOT NULL,
	first_observed_at TIMESTAMPTZ NOT NULL,
	last_observed_at  TIMESTAMPTZ NOT NULL,
	severity          TEXT NOT NULL,
	confidence        TEXT NOT NULL,
	status            TEXT NOT NULL DEFAULT 'open',
	explanation       TEXT NOT NULL,
	created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT detection_matches_status_check CHECK (status IN ('open', 'acknowledged', 'resolved', 'suppressed')),
	CONSTRAINT detection_matches_severity_check CHECK (severity IN ('informational', 'low', 'medium', 'high', 'critical')),
	CONSTRAINT detection_matches_confidence_check CHECK (confidence IN ('very_low', 'low', 'medium', 'high', 'very_high')),
	CONSTRAINT detection_matches_explanation_not_blank CHECK (btrim(explanation) <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS detection_matches_fingerprint_unique ON detection_matches (fingerprint);
CREATE INDEX IF NOT EXISTS detection_matches_target_id_idx ON detection_matches (target_id);
CREATE INDEX IF NOT EXISTS detection_matches_rule_id_idx ON detection_matches (rule_id, rule_version);
CREATE INDEX IF NOT EXISTS detection_matches_status_idx ON detection_matches (status);

-- Evidence backing a match (phase11.md §17/§63) — polymorphic source_
-- type/source_id (finding/asset_observation/endpoint_observation/
-- fingerprint_change/intelligence_record), the same deliberately-FK-less
-- design phase9.md's investigation_evidence/timeline_events already use
-- for the identical reason (one column cannot reference more than one
-- target table).
CREATE TABLE IF NOT EXISTS detection_evidence (
	id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	detection_match_id UUID NOT NULL REFERENCES detection_matches (id) ON DELETE CASCADE,
	source_type        TEXT NOT NULL,
	source_id          UUID NOT NULL,
	role               TEXT NOT NULL,
	observed_at        TIMESTAMPTZ NOT NULL,
	created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT detection_evidence_source_type_check CHECK (source_type IN (
		'finding', 'asset_observation', 'endpoint_observation', 'fingerprint_change', 'intelligence_record'
	)),
	CONSTRAINT detection_evidence_role_check CHECK (role IN ('trigger', 'supporting', 'sequence_step'))
);

CREATE UNIQUE INDEX IF NOT EXISTS detection_evidence_dedup_unique ON detection_evidence (detection_match_id, source_type, source_id, role);
CREATE INDEX IF NOT EXISTS detection_evidence_match_id_idx ON detection_evidence (detection_match_id);

-- Alerts (phase11.md §20) — reference a match rather than duplicating
-- its evidence; one alert per match (upsert on detection_match_id).
CREATE TABLE IF NOT EXISTS alerts (
	id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id          UUID NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
	detection_match_id UUID NOT NULL REFERENCES detection_matches (id) ON DELETE RESTRICT,
	title              TEXT NOT NULL,
	description        TEXT NOT NULL DEFAULT '',
	severity           TEXT NOT NULL,
	confidence         TEXT NOT NULL,
	status             TEXT NOT NULL DEFAULT 'open',
	investigation_id   UUID,
	first_observed_at  TIMESTAMPTZ NOT NULL,
	last_observed_at   TIMESTAMPTZ NOT NULL,
	created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT alerts_status_check CHECK (status IN ('open', 'acknowledged', 'investigating', 'resolved', 'suppressed')),
	CONSTRAINT alerts_severity_check CHECK (severity IN ('informational', 'low', 'medium', 'high', 'critical')),
	CONSTRAINT alerts_confidence_check CHECK (confidence IN ('very_low', 'low', 'medium', 'high', 'very_high')),
	CONSTRAINT alerts_title_not_blank CHECK (btrim(title) <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS alerts_detection_match_id_unique ON alerts (detection_match_id);
CREATE INDEX IF NOT EXISTS alerts_target_id_idx ON alerts (target_id);
CREATE INDEX IF NOT EXISTS alerts_status_idx ON alerts (status);

-- Suppressions (phase11.md §35/§36/§37) — never deleted; a removal sets
-- removed_at/removed_by, preserving the full audit history.
CREATE TABLE IF NOT EXISTS suppressions (
	id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id  UUID NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
	scope      TEXT NOT NULL,
	scope_id   UUID NOT NULL,
	reason     TEXT NOT NULL,
	created_by TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	expires_at TIMESTAMPTZ,
	removed_at TIMESTAMPTZ,
	removed_by TEXT NOT NULL DEFAULT '',
	CONSTRAINT suppressions_scope_check CHECK (scope IN ('rule', 'match', 'alert')),
	CONSTRAINT suppressions_reason_not_blank CHECK (btrim(reason) <> ''),
	CONSTRAINT suppressions_created_by_not_blank CHECK (btrim(created_by) <> '')
);

CREATE INDEX IF NOT EXISTS suppressions_scope_idx ON suppressions (scope, scope_id);
CREATE INDEX IF NOT EXISTS suppressions_target_id_idx ON suppressions (target_id);
