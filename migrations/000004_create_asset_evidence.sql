-- Phase 2: append-only evidence backing an asset. A row here is never
-- updated or deleted by the application — a changed observation is always
-- a new row (see internal/domain/asset.Evidence and
-- docs/architecture/asset-model.md).
--
-- ON DELETE CASCADE (asset_evidence -> assets) is intentional and does not
-- contradict phase2.md §16's "do not use cascading deletion where it could
-- unexpectedly erase security evidence": that warning is about the
-- targets -> assets edge (assets.target_id uses ON DELETE RESTRICT, so
-- deleting a target can never silently wipe its asset/evidence tree).
-- Evidence rows are genuinely dependent children of one specific asset row
-- — they cannot exist without it — so cascading here is ordinary
-- referential integrity, not a loss of independently-meaningful data. In
-- normal operation assets are never hard-deleted anyway (see §34 / Retire).
CREATE TABLE IF NOT EXISTS asset_evidence (
	id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	asset_id              UUID NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
	source                TEXT NOT NULL,
	evidence_type         TEXT NOT NULL,
	evidence_data         JSONB NOT NULL DEFAULT '{}'::jsonb,
	evidence_fingerprint  CHAR(64) NOT NULL,
	confidence            DOUBLE PRECISION NOT NULL DEFAULT 0,
	observed_at           TIMESTAMPTZ NOT NULL,
	created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT asset_evidence_type_check CHECK (evidence_type IN (
		'DNS_RECORD', 'HTTP_RESPONSE', 'TLS_CERTIFICATE', 'PORT_OBSERVATION',
		'HEADER', 'HTML', 'REPOSITORY_REFERENCE', 'CLOUD_REFERENCE', 'MANUAL'
	)),
	CONSTRAINT asset_evidence_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
	CONSTRAINT asset_evidence_source_not_blank CHECK (btrim(source) <> '')
);

-- Deduplication boundary: identical evidence (same asset, source, type, and
-- fingerprint of its sanitized data) is stored once, not once per scan —
-- see internal/domain/asset.EvidenceFingerprint and the ON CONFLICT DO
-- NOTHING upsert in internal/repository/asset.CreateEvidence.
CREATE UNIQUE INDEX IF NOT EXISTS asset_evidence_dedup_unique
	ON asset_evidence (asset_id, source, evidence_type, evidence_fingerprint);

-- Lookup patterns: every evidence row for one asset (the only query this
-- table currently serves), ordered/filtered by observation recency.
CREATE INDEX IF NOT EXISTS asset_evidence_asset_id_idx ON asset_evidence (asset_id);
CREATE INDEX IF NOT EXISTS asset_evidence_observed_at_idx ON asset_evidence (observed_at);
