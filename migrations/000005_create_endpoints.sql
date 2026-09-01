-- Phase 2: network/application endpoints observed on an asset. url/scheme/
-- host/port/path are always the normalized form produced by
-- internal/domain/endpoint.Normalize — never the raw, as-observed URL — so
-- the (asset_id, method, url) uniqueness constraint below is exactly the
-- endpoint identity/deduplication strategy documented in
-- docs/architecture/asset-model.md.
--
-- ON DELETE CASCADE (endpoints -> assets): endpoints are dependent child
-- records of one specific asset row, the same reasoning as
-- asset_evidence -> assets in 000004; see that migration's comment for why
-- this doesn't conflict with phase2.md §16.
CREATE TABLE IF NOT EXISTS endpoints (
	id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	asset_id       UUID NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
	url            TEXT NOT NULL,
	method         TEXT NOT NULL,
	scheme         TEXT NOT NULL,
	host           TEXT NOT NULL,
	port           INTEGER NOT NULL,
	path           TEXT NOT NULL,
	query_pattern  TEXT NOT NULL DEFAULT '',
	content_type   TEXT,
	status_code    INTEGER,
	response_hash  TEXT,
	first_seen     TIMESTAMPTZ NOT NULL,
	last_seen      TIMESTAMPTZ NOT NULL,
	status         TEXT NOT NULL DEFAULT 'DISCOVERED',
	metadata       JSONB NOT NULL DEFAULT '{}'::jsonb,
	created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT endpoints_method_check
		CHECK (method IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS')),
	CONSTRAINT endpoints_status_check
		CHECK (status IN ('DISCOVERED', 'ACTIVE', 'INACTIVE', 'UNKNOWN', 'RETIRED')),
	CONSTRAINT endpoints_port_range CHECK (port BETWEEN 1 AND 65535),
	CONSTRAINT endpoints_status_code_range CHECK (status_code IS NULL OR (status_code BETWEEN 100 AND 599))
);

-- Deduplication boundary: the same method against the same normalized URL,
-- on the same asset, is always one row (internal/repository/endpoint.Upsert
-- relies on this constraint's ON CONFLICT target).
CREATE UNIQUE INDEX IF NOT EXISTS endpoints_asset_method_url_unique ON endpoints (asset_id, method, url);

-- Lookup patterns: every endpoint for one asset (the primary query),
-- looking up by URL, and ordering/filtering by observation recency.
CREATE INDEX IF NOT EXISTS endpoints_asset_id_idx ON endpoints (asset_id);
CREATE INDEX IF NOT EXISTS endpoints_url_idx ON endpoints (url);
CREATE INDEX IF NOT EXISTS endpoints_last_seen_idx ON endpoints (last_seen);
