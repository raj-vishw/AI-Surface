-- Phase 2: the authorized scope a scan may operate against. A target
-- existing in this table is never, by itself, permission to act against it
-- — see authorization_status and internal/domain/target.Target.IsAuthorized.
--
-- gen_random_uuid() is built into PostgreSQL core as of version 13 (no
-- pgcrypto extension required); this project targets postgres:16-alpine.
CREATE TABLE IF NOT EXISTS targets (
	id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	name                  TEXT NOT NULL,
	type                  TEXT NOT NULL,
	value                 TEXT NOT NULL,
	description           TEXT NOT NULL DEFAULT '',
	authorization_status  TEXT NOT NULL DEFAULT 'UNVERIFIED',
	created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT targets_type_check
		CHECK (type IN ('DOMAIN', 'HOST', 'IP', 'CIDR', 'URL', 'REPOSITORY', 'CLOUD_ACCOUNT')),
	CONSTRAINT targets_authorization_status_check
		CHECK (authorization_status IN ('UNVERIFIED', 'AUTHORIZED', 'EXPIRED', 'REVOKED')),
	CONSTRAINT targets_name_not_blank CHECK (btrim(name) <> ''),
	CONSTRAINT targets_value_not_blank CHECK (btrim(value) <> '')
);

-- Deterministic duplicate detection: the same (type, value) pair always
-- identifies the same real-world target (internal/service/target checks
-- this before creating a new row).
CREATE UNIQUE INDEX IF NOT EXISTS targets_type_value_unique ON targets (type, value);

-- Lookup patterns this index set supports: filtering the target list by
-- type, filtering/joining by authorization status (future phases gate
-- active scanning on this), and the duplicate-detection lookup above
-- (covered by the unique index itself, so no separate value-only index).
CREATE INDEX IF NOT EXISTS targets_type_idx ON targets (type);
CREATE INDEX IF NOT EXISTS targets_authorization_status_idx ON targets (authorization_status);
