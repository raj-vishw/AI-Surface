-- Phase 1: no product tables yet. This migration exists so the migration
-- system itself (embedding, ordering, transactional apply, bookkeeping) is
-- exercised end-to-end before any real schema is introduced.
--
-- schema_migrations itself is created by the migration runner before this
-- file runs; this statement is idempotent so re-running Up() is safe.
CREATE TABLE IF NOT EXISTS schema_migrations (
	version     INTEGER PRIMARY KEY,
	description TEXT NOT NULL,
	applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
