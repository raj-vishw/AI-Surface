-- Phase 6: passive technology fingerprints, mirroring the assets/
-- asset_evidence duality (000003/000004) exactly — see
-- internal/domain/fingerprint and docs/architecture/fingerprinting.md.
--
-- fingerprints is "current state": one row per (asset_id, category,
-- normalized technology) identity, upserted like assets — FirstSeen is
-- preserved, LastSeen advances, and a fingerprint that stops matching in
-- the most recent analysis run moves to status INACTIVE rather than being
-- deleted (phase6.md §22's "do not delete historical observations").
--
-- fingerprint_evidence is the append-only historical trail: one immutable
-- row per distinct matched-signal-set snapshot ever observed for a
-- fingerprint, the same role asset_evidence plays for assets.
--
-- ON DELETE CASCADE (fingerprints -> assets, fingerprint_evidence ->
-- fingerprints) mirrors asset_evidence's own justification (000004): both
-- are genuinely dependent child rows that cannot exist without their
-- parent, not independently-meaningful security evidence whose loss
-- would be surprising — assets themselves are never hard-deleted in
-- normal operation (see 000003's Retire/soft-delete discussion).
CREATE TABLE IF NOT EXISTS fingerprints (
	id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	asset_id     UUID NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
	target_id    UUID NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
	scan_id      UUID,
	category     TEXT NOT NULL,
	technology   TEXT NOT NULL,
	product      TEXT NOT NULL DEFAULT '',
	vendor       TEXT NOT NULL DEFAULT '',
	version      TEXT NOT NULL DEFAULT '',
	confidence   DOUBLE PRECISION NOT NULL DEFAULT 0,
	status       TEXT NOT NULL DEFAULT 'ACTIVE',
	identity_key TEXT NOT NULL,
	metadata     JSONB NOT NULL DEFAULT '{}'::jsonb,
	first_seen   TIMESTAMPTZ NOT NULL,
	last_seen    TIMESTAMPTZ NOT NULL,
	created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT fingerprints_category_check CHECK (category IN (
		'web_server', 'reverse_proxy', 'framework', 'frontend', 'runtime',
		'programming_language', 'cms', 'api', 'cloud', 'cdn', 'database',
		'authentication', 'monitoring', 'analytics', 'ai_provider',
		'ai_platform', 'ai_model_candidate', 'service', 'library', 'infrastructure'
	)),
	CONSTRAINT fingerprints_status_check CHECK (status IN ('ACTIVE', 'INACTIVE')),
	CONSTRAINT fingerprints_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
	CONSTRAINT fingerprints_technology_not_blank CHECK (btrim(technology) <> ''),
	CONSTRAINT fingerprints_identity_key_not_blank CHECK (btrim(identity_key) <> '')
);

-- The deduplication/upsert boundary: within one asset, one identity_key
-- (asset_id + category + normalized technology, see
-- internal/domain/fingerprint.IdentityKey) is always exactly one row,
-- regardless of how many analysis runs observe it — see
-- internal/repository/fingerprint.Upsert's single atomic ON CONFLICT
-- statement.
CREATE UNIQUE INDEX IF NOT EXISTS fingerprints_asset_identity_unique ON fingerprints (asset_id, identity_key);

-- Lookup patterns (phase6.md §21): every fingerprint for an asset (most
-- common), filtering/reporting by technology, category, scan, confidence,
-- and "current" (status = ACTIVE) fingerprints specifically.
CREATE INDEX IF NOT EXISTS fingerprints_asset_id_idx ON fingerprints (asset_id);
CREATE INDEX IF NOT EXISTS fingerprints_target_id_idx ON fingerprints (target_id);
CREATE INDEX IF NOT EXISTS fingerprints_technology_idx ON fingerprints (technology);
CREATE INDEX IF NOT EXISTS fingerprints_category_idx ON fingerprints (category);
CREATE INDEX IF NOT EXISTS fingerprints_scan_id_idx ON fingerprints (scan_id);
CREATE INDEX IF NOT EXISTS fingerprints_confidence_idx ON fingerprints (confidence);
CREATE INDEX IF NOT EXISTS fingerprints_status_idx ON fingerprints (status);

-- Append-only evidence backing a fingerprint (mirrors asset_evidence,
-- 000004, exactly) — a row here is never updated or deleted; a changed
-- signal set is always a new row.
CREATE TABLE IF NOT EXISTS fingerprint_evidence (
	id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	fingerprint_id UUID NOT NULL REFERENCES fingerprints (id) ON DELETE CASCADE,
	asset_id       UUID NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
	scan_id        UUID,
	source         TEXT NOT NULL DEFAULT 'fingerprint',
	signals        JSONB NOT NULL DEFAULT '[]'::jsonb,
	signals_fingerprint CHAR(64) NOT NULL,
	confidence     DOUBLE PRECISION NOT NULL DEFAULT 0,
	observed_at    TIMESTAMPTZ NOT NULL,
	created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT fingerprint_evidence_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
	CONSTRAINT fingerprint_evidence_source_not_blank CHECK (btrim(source) <> '')
);

-- Deduplication boundary: an unchanged signal set is stored once per
-- fingerprint, not once per analysis run (the same "scan_id is deliberately
-- excluded from the hashed shape" discipline asset_evidence applies — see
-- internal/service/fingerprint).
CREATE UNIQUE INDEX IF NOT EXISTS fingerprint_evidence_dedup_unique
	ON fingerprint_evidence (fingerprint_id, signals_fingerprint);

CREATE INDEX IF NOT EXISTS fingerprint_evidence_fingerprint_id_idx ON fingerprint_evidence (fingerprint_id);
CREATE INDEX IF NOT EXISTS fingerprint_evidence_asset_id_idx ON fingerprint_evidence (asset_id);
CREATE INDEX IF NOT EXISTS fingerprint_evidence_observed_at_idx ON fingerprint_evidence (observed_at);
