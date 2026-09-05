-- Phase 10: threat intelligence & risk enrichment — see
-- internal/domain/intelligence and
-- docs/architecture/threat-intelligence.md.
--
-- intelligence_records is the append-only, provenance-tagged store of
-- every provider's observation about an indicator (phase10.md §2/§3/§47):
-- a record is never overwritten, and multiple providers' (possibly
-- disagreeing) records for the same indicator all coexist — see
-- internal/intelligence.Aggregate for the read-time, conflict-preserving
-- view built from these rows.
CREATE TABLE IF NOT EXISTS intelligence_records (
	id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id        UUID NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
	indicator_type   TEXT NOT NULL,
	indicator_value  TEXT NOT NULL,
	provider_id      TEXT NOT NULL,
	provider_version TEXT NOT NULL DEFAULT '',
	source_type      TEXT NOT NULL,
	category         TEXT NOT NULL DEFAULT '',
	verdict          TEXT NOT NULL DEFAULT 'unknown',
	confidence       TEXT NOT NULL DEFAULT 'unknown',
	first_seen       TIMESTAMPTZ,
	last_seen        TIMESTAMPTZ,
	expiration       TIMESTAMPTZ,
	retrieved_at     TIMESTAMPTZ NOT NULL,
	source_reference TEXT NOT NULL DEFAULT '',
	normalized_data  JSONB NOT NULL DEFAULT '{}'::jsonb,
	tags             TEXT[] NOT NULL DEFAULT '{}',
	created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT intelligence_records_indicator_type_check CHECK (indicator_type IN (
		'domain', 'subdomain', 'ipv4', 'ipv6', 'url', 'hostname', 'certificate', 'technology', 'hash'
	)),
	CONSTRAINT intelligence_records_source_type_check CHECK (source_type IN (
		'local', 'dns', 'certificate', 'technology', 'vulnerability', 'reputation', 'threat_feed'
	)),
	CONSTRAINT intelligence_records_verdict_check CHECK (verdict IN ('benign', 'suspicious', 'malicious', 'unknown')),
	CONSTRAINT intelligence_records_confidence_check CHECK (confidence IN ('unknown', 'low', 'medium', 'high')),
	CONSTRAINT intelligence_records_provider_id_not_blank CHECK (btrim(provider_id) <> ''),
	CONSTRAINT intelligence_records_indicator_value_not_blank CHECK (btrim(indicator_value) <> '')
);

-- One (provider, indicator) pair may be re-observed over time (a refresh,
-- a new scan) — re-recording widens first_seen/last_seen on the existing
-- row rather than accumulating unbounded duplicate rows for an unchanged
-- observation. A genuinely different observation (different verdict/
-- confidence/source_reference) is a separate insert instead — see
-- internal/repository/intelligence's Upsert doc comment.
CREATE UNIQUE INDEX IF NOT EXISTS intelligence_records_dedup_unique
	ON intelligence_records (target_id, provider_id, indicator_type, indicator_value, verdict, confidence, source_reference);

CREATE INDEX IF NOT EXISTS intelligence_records_target_id_idx ON intelligence_records (target_id);
CREATE INDEX IF NOT EXISTS intelligence_records_indicator_idx ON intelligence_records (indicator_type, indicator_value);
CREATE INDEX IF NOT EXISTS intelligence_records_provider_id_idx ON intelligence_records (provider_id);
CREATE INDEX IF NOT EXISTS intelligence_records_expiration_idx ON intelligence_records (expiration);
CREATE INDEX IF NOT EXISTS intelligence_records_retrieved_at_idx ON intelligence_records (retrieved_at);

-- Persistent provider-result cache (phase10.md §23) — a Postgres-backed
-- implementation of internal/intelligence.Cache, reusing the platform's
-- existing database rather than standing up new caching infrastructure
-- (phase10.md §1's "do not create duplicate infrastructure"; this
-- project's only other cache-adjacent infra, internal/redis, is a bare
-- connectivity client with no cache abstraction of its own).
CREATE TABLE IF NOT EXISTS intelligence_cache (
	provider_id     TEXT NOT NULL,
	indicator_type  TEXT NOT NULL,
	indicator_value TEXT NOT NULL,
	records         JSONB NOT NULL DEFAULT '[]'::jsonb,
	cached_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	expires_at      TIMESTAMPTZ,
	PRIMARY KEY (provider_id, indicator_type, indicator_value)
);

CREATE INDEX IF NOT EXISTS intelligence_cache_expires_at_idx ON intelligence_cache (expires_at);

-- Vulnerability catalog (phase10.md §12) — reusable across many matches.
-- Seeded from this platform's own built-in seed data
-- (internal/intelligence/providers seeds none directly; see
-- internal/service/intelligence's seed catalog) and never auto-generated.
CREATE TABLE IF NOT EXISTS vulnerability_records (
	id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	identifier          TEXT NOT NULL,
	title               TEXT NOT NULL,
	description         TEXT NOT NULL DEFAULT '',
	severity            TEXT NOT NULL,
	affected_product    TEXT NOT NULL,
	version_constraints TEXT[] NOT NULL DEFAULT '{}',
	"references"        TEXT[] NOT NULL DEFAULT '{}',
	published_at        TIMESTAMPTZ,
	modified_at         TIMESTAMPTZ,
	created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT vulnerability_records_severity_check CHECK (severity IN ('informational', 'low', 'medium', 'high', 'critical')),
	CONSTRAINT vulnerability_records_identifier_not_blank CHECK (btrim(identifier) <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS vulnerability_records_identifier_unique ON vulnerability_records (identifier);
CREATE INDEX IF NOT EXISTS vulnerability_records_affected_product_idx ON vulnerability_records (affected_product);

-- Vulnerability matches (phase10.md §14/§16) — every field the matching
-- logic used is preserved so a match is never presented as a confirmed
-- vulnerability without the evidence to back it (see match_status_check
-- and evidence/matching_rule NOT NULL below).
CREATE TABLE IF NOT EXISTS vulnerability_matches (
	id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id          UUID NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
	asset_id           UUID NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
	finding_id         UUID REFERENCES findings (id) ON DELETE SET NULL,
	vulnerability_id   UUID NOT NULL REFERENCES vulnerability_records (id) ON DELETE RESTRICT,
	affected_component TEXT NOT NULL DEFAULT '',
	observed_product   TEXT NOT NULL DEFAULT '',
	observed_version   TEXT NOT NULL DEFAULT '',
	match_status       TEXT NOT NULL,
	confidence         TEXT NOT NULL DEFAULT 'unknown',
	evidence           TEXT NOT NULL,
	matching_rule      TEXT NOT NULL,
	created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT vulnerability_matches_status_check CHECK (match_status IN ('confirmed', 'probable', 'insufficient_evidence', 'no_match')),
	CONSTRAINT vulnerability_matches_confidence_check CHECK (confidence IN ('unknown', 'low', 'medium', 'high')),
	CONSTRAINT vulnerability_matches_evidence_not_blank CHECK (btrim(evidence) <> ''),
	CONSTRAINT vulnerability_matches_rule_not_blank CHECK (btrim(matching_rule) <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS vulnerability_matches_dedup_unique
	ON vulnerability_matches (asset_id, vulnerability_id, observed_version);
CREATE INDEX IF NOT EXISTS vulnerability_matches_target_id_idx ON vulnerability_matches (target_id);
CREATE INDEX IF NOT EXISTS vulnerability_matches_asset_id_idx ON vulnerability_matches (asset_id);
CREATE INDEX IF NOT EXISTS vulnerability_matches_finding_id_idx ON vulnerability_matches (finding_id);
CREATE INDEX IF NOT EXISTS vulnerability_matches_vulnerability_id_idx ON vulnerability_matches (vulnerability_id);

-- Risk scores (phase10.md §33/§43/§45/§46) — append-only: a
-- recalculation always inserts a new row rather than overwriting the
-- previous one, so risk_over_time history is queryable directly from
-- this table (no separate risk_history table is needed).
CREATE TABLE IF NOT EXISTS risk_scores (
	id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id     UUID NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
	entity_type   TEXT NOT NULL,
	entity_id     UUID NOT NULL,
	score         INTEGER NOT NULL,
	severity      TEXT NOT NULL,
	confidence    TEXT NOT NULL DEFAULT 'unknown',
	model_version TEXT NOT NULL,
	factors       JSONB NOT NULL DEFAULT '[]'::jsonb,
	explanation   TEXT NOT NULL DEFAULT '',
	calculated_at TIMESTAMPTZ NOT NULL,
	created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT risk_scores_entity_type_check CHECK (entity_type IN ('asset', 'finding', 'investigation')),
	CONSTRAINT risk_scores_score_range CHECK (score >= 0 AND score <= 100),
	CONSTRAINT risk_scores_severity_check CHECK (severity IN ('informational', 'low', 'medium', 'high', 'critical')),
	CONSTRAINT risk_scores_confidence_check CHECK (confidence IN ('unknown', 'low', 'medium', 'high'))
);

CREATE INDEX IF NOT EXISTS risk_scores_target_id_idx ON risk_scores (target_id);
CREATE INDEX IF NOT EXISTS risk_scores_entity_idx ON risk_scores (entity_type, entity_id, calculated_at DESC);

-- Enrichment events (phase10.md §48-51) — a lightweight, append-only
-- change log; this platform stops at producing the event, it does not
-- implement notification delivery (phase10.md §49).
CREATE TABLE IF NOT EXISTS enrichment_events (
	id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id       UUID NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
	indicator_type  TEXT NOT NULL DEFAULT '',
	indicator_value TEXT NOT NULL DEFAULT '',
	event_type      TEXT NOT NULL,
	source          TEXT NOT NULL,
	source_id       TEXT NOT NULL DEFAULT '',
	"timestamp"     TIMESTAMPTZ NOT NULL,
	previous_value  TEXT NOT NULL DEFAULT '',
	new_value       TEXT NOT NULL DEFAULT '',
	confidence      TEXT NOT NULL DEFAULT 'unknown',
	created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT enrichment_events_type_check CHECK (event_type IN (
		'verdict_changed', 'confidence_changed', 'new_malicious_reputation',
		'vulnerability_match_created', 'vulnerability_severity_increased',
		'risk_score_increased', 'intelligence_conflict', 'provider_enabled', 'provider_disabled'
	)),
	CONSTRAINT enrichment_events_source_not_blank CHECK (btrim(source) <> '')
);

CREATE INDEX IF NOT EXISTS enrichment_events_target_id_idx ON enrichment_events (target_id);
CREATE INDEX IF NOT EXISTS enrichment_events_indicator_idx ON enrichment_events (indicator_type, indicator_value);
CREATE INDEX IF NOT EXISTS enrichment_events_timestamp_idx ON enrichment_events ("timestamp");

-- Asset criticality (phase10.md §36) — analyst/business context, a
-- mutable "current state" row (like fingerprints.status), never inferred
-- from a hostname or any other observed signal.
CREATE TABLE IF NOT EXISTS asset_criticality (
	asset_id    UUID PRIMARY KEY REFERENCES assets (id) ON DELETE CASCADE,
	target_id   UUID NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
	criticality TEXT NOT NULL,
	set_by      TEXT NOT NULL,
	set_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT asset_criticality_check CHECK (criticality IN ('low', 'normal', 'high', 'critical')),
	CONSTRAINT asset_criticality_set_by_not_blank CHECK (btrim(set_by) <> '')
);

CREATE INDEX IF NOT EXISTS asset_criticality_target_id_idx ON asset_criticality (target_id);
