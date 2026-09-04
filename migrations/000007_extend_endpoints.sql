-- Phase 7: extends the existing endpoints table (000005) for endpoint
-- discovery, per the explicit instruction to extend rather than duplicate
-- when an Endpoint model already exists. Endpoint identity is unchanged
-- (asset_id, method, url) — url is already the fully normalized form
-- (internal/domain/endpoint.Normalize), which already satisfies
-- phase7.md §7/§8's identity/normalization requirements (hostname casing,
-- default ports, dot segments, trailing slash, fragment removal, query
-- parameter *names* only). No new "normalized_path" column is added —
-- `path` already is that value.
ALTER TABLE endpoints
	ADD COLUMN IF NOT EXISTS scan_id        UUID,
	ADD COLUMN IF NOT EXISTS content_length BIGINT,
	ADD COLUMN IF NOT EXISTS classification TEXT NOT NULL DEFAULT 'unknown',
	ADD COLUMN IF NOT EXISTS api_type       TEXT NOT NULL DEFAULT '',
	ADD COLUMN IF NOT EXISTS api_version    TEXT NOT NULL DEFAULT '',
	-- sources is a plain TEXT[] (not JSONB) — a Postgres array
	-- union/dedup (array(select distinct unnest(a || b))) is simpler and
	-- more idiomatic than the equivalent JSONB expression for "one
	-- endpoint discovered via html AND javascript AND openapi"
	-- (phase7.md §40).
	ADD COLUMN IF NOT EXISTS sources        TEXT[] NOT NULL DEFAULT '{}',
	ADD COLUMN IF NOT EXISTS confidence     DOUBLE PRECISION NOT NULL DEFAULT 0,
	-- documented/observed/inferred are independent, monotonic-OR facts
	-- (phase7.md §46/§47) — see internal/domain/endpoint.Endpoint's doc
	-- comment.
	ADD COLUMN IF NOT EXISTS documented     BOOLEAN NOT NULL DEFAULT false,
	ADD COLUMN IF NOT EXISTS observed       BOOLEAN NOT NULL DEFAULT false,
	ADD COLUMN IF NOT EXISTS inferred       BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE endpoints
	ADD CONSTRAINT endpoints_classification_check CHECK (classification IN (
		'page', 'api', 'graphql', 'openapi', 'swagger', 'auth', 'static',
		'asset', 'documentation', 'sitemap', 'robots', 'websocket_candidate', 'unknown'
	)),
	ADD CONSTRAINT endpoints_confidence_range CHECK (confidence >= 0 AND confidence <= 1);

CREATE INDEX IF NOT EXISTS endpoints_scan_id_idx ON endpoints (scan_id);
CREATE INDEX IF NOT EXISTS endpoints_classification_idx ON endpoints (classification);
CREATE INDEX IF NOT EXISTS endpoints_path_idx ON endpoints (path);

-- Append-only evidence backing an endpoint (mirrors asset_evidence/
-- fingerprint_evidence exactly — see 000004/000006) — one immutable row
-- per distinct sanitized evidence snapshot ever observed, deduplicated by
-- fingerprint, never updated or deleted.
CREATE TABLE IF NOT EXISTS endpoint_evidence (
	id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	endpoint_id           UUID NOT NULL REFERENCES endpoints (id) ON DELETE CASCADE,
	asset_id              UUID NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
	scan_id               UUID,
	source                TEXT NOT NULL,
	evidence_data         JSONB NOT NULL DEFAULT '{}'::jsonb,
	evidence_fingerprint  CHAR(64) NOT NULL,
	confidence            DOUBLE PRECISION NOT NULL DEFAULT 0,
	observed_at           TIMESTAMPTZ NOT NULL,
	created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT endpoint_evidence_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
	CONSTRAINT endpoint_evidence_source_not_blank CHECK (btrim(source) <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS endpoint_evidence_dedup_unique
	ON endpoint_evidence (endpoint_id, source, evidence_fingerprint);
CREATE INDEX IF NOT EXISTS endpoint_evidence_endpoint_id_idx ON endpoint_evidence (endpoint_id);
CREATE INDEX IF NOT EXISTS endpoint_evidence_asset_id_idx ON endpoint_evidence (asset_id);
CREATE INDEX IF NOT EXISTS endpoint_evidence_observed_at_idx ON endpoint_evidence (observed_at);

-- Structured parameter names observed for an endpoint — never values
-- (phase7.md §9/§37: "parameter name, not actual value"). A plain child
-- table (rather than a JSONB array column on endpoints) because
-- parameters benefit from being independently queryable/indexable and
-- have their own small lifecycle (location: query/path/form).
CREATE TABLE IF NOT EXISTS endpoint_parameters (
	id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	endpoint_id UUID NOT NULL REFERENCES endpoints (id) ON DELETE CASCADE,
	name        TEXT NOT NULL,
	location    TEXT NOT NULL,
	first_seen  TIMESTAMPTZ NOT NULL,
	last_seen   TIMESTAMPTZ NOT NULL,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT endpoint_parameters_location_check CHECK (location IN ('query', 'path', 'form')),
	CONSTRAINT endpoint_parameters_name_not_blank CHECK (btrim(name) <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS endpoint_parameters_unique ON endpoint_parameters (endpoint_id, name, location);
CREATE INDEX IF NOT EXISTS endpoint_parameters_endpoint_id_idx ON endpoint_parameters (endpoint_id);
