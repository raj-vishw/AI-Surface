-- Phase 2: the canonical asset inventory. Every row is one deduplicated,
-- deterministically-identified thing discovered within a target's scope —
-- see internal/domain/asset.Identity for how identity_key is computed and
-- docs/architecture/asset-model.md for the full dedup/upsert strategy.
--
-- organization_id is reserved for the multi-tenancy phase (explicitly out
-- of scope here — see doc_by_me/phase2.md §2/§43): the column exists now so
-- that phase doesn't require a backfill migration, but it carries no
-- foreign key yet because no organizations table exists.
--
-- ip is INET rather than TEXT so PostgreSQL enforces well-formed addresses
-- and supports network-aware indexing/queries; the repository layer reads
-- it back via an explicit ip::text cast and writes it via a
-- netip.Prefix-encoded parameter (see internal/repository/asset).
CREATE TABLE IF NOT EXISTS assets (
	id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id        UUID NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
	organization_id  UUID,
	type             TEXT NOT NULL,
	hostname         TEXT,
	ip               INET,
	port             INTEGER,
	protocol         TEXT,
	url              TEXT,
	technology       TEXT,
	provider         TEXT,
	model            TEXT,
	environment      TEXT,
	source           TEXT NOT NULL,
	identity_key     TEXT NOT NULL,
	first_seen       TIMESTAMPTZ NOT NULL,
	last_seen        TIMESTAMPTZ NOT NULL,
	status           TEXT NOT NULL DEFAULT 'DISCOVERED',
	confidence       DOUBLE PRECISION NOT NULL DEFAULT 0,
	metadata         JSONB NOT NULL DEFAULT '{}'::jsonb,
	created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT assets_type_check CHECK (type IN (
		'DOMAIN', 'SUBDOMAIN', 'HOST', 'IP', 'PORT', 'SERVICE',
		'HTTP_ENDPOINT', 'API_ENDPOINT', 'AI_ENDPOINT', 'REPOSITORY',
		'CLOUD_RESOURCE', 'MODEL_ENDPOINT'
	)),
	CONSTRAINT assets_status_check
		CHECK (status IN ('DISCOVERED', 'ACTIVE', 'INACTIVE', 'UNKNOWN', 'RETIRED')),
	CONSTRAINT assets_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
	CONSTRAINT assets_port_range CHECK (port IS NULL OR (port BETWEEN 1 AND 65535)),
	CONSTRAINT assets_source_not_blank CHECK (btrim(source) <> ''),
	CONSTRAINT assets_identity_key_not_blank CHECK (btrim(identity_key) <> '')
);

-- The deduplication boundary: within one target, one identity_key is
-- always exactly one row, regardless of how many discovery sources or
-- concurrent workers observe it (internal/repository/asset.Upsert relies on
-- this constraint's ON CONFLICT target for a single atomic, race-free
-- statement — see §29/§39 of phase2.md).
CREATE UNIQUE INDEX IF NOT EXISTS assets_target_identity_unique ON assets (target_id, identity_key);

-- Lookup patterns this index set supports: every asset belonging to a
-- target (the most common query), per-organization filtering (future
-- multi-tenancy), filtering by type/hostname/ip/status, and ordering the
-- inventory by recency of observation.
CREATE INDEX IF NOT EXISTS assets_target_id_idx ON assets (target_id);
CREATE INDEX IF NOT EXISTS assets_organization_id_idx ON assets (organization_id);
CREATE INDEX IF NOT EXISTS assets_type_idx ON assets (type);
CREATE INDEX IF NOT EXISTS assets_hostname_idx ON assets (hostname);
CREATE INDEX IF NOT EXISTS assets_ip_idx ON assets (ip);
CREATE INDEX IF NOT EXISTS assets_last_seen_idx ON assets (last_seen);
CREATE INDEX IF NOT EXISTS assets_status_idx ON assets (status);
