-- Phase 12: correlation engine & attack-chain analysis — see
-- internal/domain/correlation and docs/architecture/correlation-engine.md.
--
-- correlations holds one system-suggested (or analyst-confirmed)
-- grouping of related security observations (phase12.md §4). It is never
-- hard-deleted, and Status only ever reaches 'confirmed'/'dismissed'
-- through an explicit analyst action (see confirmed_by/dismissal_reason
-- below and internal/service/correlation.Confirm/Dismiss).
CREATE TABLE IF NOT EXISTS correlations (
	id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id          UUID NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
	title              TEXT NOT NULL,
	description        TEXT NOT NULL DEFAULT '',
	status             TEXT NOT NULL DEFAULT 'open',
	severity           TEXT NOT NULL,
	confidence         TEXT NOT NULL,
	score              INT NOT NULL,
	fingerprint        TEXT NOT NULL,
	model_version      TEXT NOT NULL DEFAULT 'v1',
	first_observed_at  TIMESTAMPTZ NOT NULL,
	last_observed_at   TIMESTAMPTZ NOT NULL,
	investigation_id   UUID REFERENCES investigations (id) ON DELETE SET NULL,
	confirmed_by       TEXT NOT NULL DEFAULT '',
	confirmed_at       TIMESTAMPTZ,
	confirmation_notes TEXT NOT NULL DEFAULT '',
	dismissed_by       TEXT NOT NULL DEFAULT '',
	dismissed_at       TIMESTAMPTZ,
	dismissal_reason   TEXT NOT NULL DEFAULT '',
	-- merged_into_id/merged_from_ids/split_from_id implement phase12.md
	-- §29/§30's merge/split lineage directly on this table rather than
	-- via separate correlation_merges/correlation_splits tables — a
	-- correlation row is never deleted, so its own id already IS the
	-- permanent audit record; a second table would only duplicate the
	-- same (source id, target id, timestamp) fact.
	merged_into_id     UUID REFERENCES correlations (id) ON DELETE SET NULL,
	merged_from_ids    JSONB NOT NULL DEFAULT '[]',
	split_from_id      UUID REFERENCES correlations (id) ON DELETE SET NULL,
	created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT correlations_status_check CHECK (status IN ('open', 'investigating', 'confirmed', 'resolved', 'dismissed')),
	CONSTRAINT correlations_severity_check CHECK (severity IN ('informational', 'low', 'medium', 'high', 'critical')),
	CONSTRAINT correlations_confidence_check CHECK (confidence IN ('low', 'medium', 'high')),
	CONSTRAINT correlations_score_range CHECK (score BETWEEN 0 AND 100),
	CONSTRAINT correlations_title_not_blank CHECK (btrim(title) <> ''),
	CONSTRAINT correlations_confirmed_requires_actor CHECK (status <> 'confirmed' OR btrim(confirmed_by) <> ''),
	CONSTRAINT correlations_dismissed_requires_reason CHECK (status <> 'dismissed' OR btrim(dismissal_reason) <> '')
);

-- Deduplication key (phase12.md §27/§28): re-evaluating the same
-- underlying node set within the same window must never create a
-- duplicate correlation.
CREATE UNIQUE INDEX IF NOT EXISTS correlations_fingerprint_unique ON correlations (fingerprint);
CREATE INDEX IF NOT EXISTS correlations_target_id_idx ON correlations (target_id);
CREATE INDEX IF NOT EXISTS correlations_status_idx ON correlations (status);
CREATE INDEX IF NOT EXISTS correlations_severity_idx ON correlations (severity);
CREATE INDEX IF NOT EXISTS correlations_confidence_idx ON correlations (confidence);
CREATE INDEX IF NOT EXISTS correlations_first_observed_at_idx ON correlations (first_observed_at);
CREATE INDEX IF NOT EXISTS correlations_last_observed_at_idx ON correlations (last_observed_at);
CREATE INDEX IF NOT EXISTS correlations_merged_into_id_idx ON correlations (merged_into_id);

-- correlation_nodes doubles as this platform's CorrelationEvidence
-- record (phase12.md §5/§7) — see
-- internal/domain/correlation.CorrelationNode's doc comment for why a
-- second, parallel evidence table was not introduced. A node is a
-- reference only: (type, reference_id) points at an already-persisted
-- finding/asset/detection_match/alert/endpoint/intelligence_record/
-- investigation row, never a copy of it.
CREATE TABLE IF NOT EXISTS correlation_nodes (
	id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	correlation_id UUID NOT NULL REFERENCES correlations (id) ON DELETE CASCADE,
	type           TEXT NOT NULL,
	reference_id   UUID NOT NULL,
	role           TEXT NOT NULL DEFAULT 'supporting',
	"timestamp"    TIMESTAMPTZ NOT NULL,
	attributes     JSONB NOT NULL DEFAULT '{}',
	created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT correlation_nodes_type_check CHECK (type IN
		('finding', 'detection_match', 'alert', 'asset', 'endpoint', 'intelligence_record', 'investigation')),
	CONSTRAINT correlation_nodes_role_check CHECK (role IN ('trigger', 'supporting'))
);

CREATE UNIQUE INDEX IF NOT EXISTS correlation_nodes_unique ON correlation_nodes (correlation_id, type, reference_id);
CREATE INDEX IF NOT EXISTS correlation_nodes_correlation_id_idx ON correlation_nodes (correlation_id);
CREATE INDEX IF NOT EXISTS correlation_nodes_reference_idx ON correlation_nodes (type, reference_id);

-- correlation_edges is one Strategy's explained relationship between two
-- nodes (phase12.md §8) — always traceable to exactly one
-- (strategy_id, strategy_version) pair, the same discipline phase11.md
-- §4 established for detection_matches' (rule_id, rule_version).
CREATE TABLE IF NOT EXISTS correlation_edges (
	id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	correlation_id   UUID NOT NULL REFERENCES correlations (id) ON DELETE CASCADE,
	source_node_id   UUID NOT NULL REFERENCES correlation_nodes (id) ON DELETE CASCADE,
	target_node_id   UUID NOT NULL REFERENCES correlation_nodes (id) ON DELETE CASCADE,
	relationship     TEXT NOT NULL,
	provenance       TEXT NOT NULL,
	confidence       TEXT NOT NULL,
	evidence         TEXT NOT NULL,
	strategy_id      TEXT NOT NULL,
	strategy_version INT NOT NULL,
	created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT correlation_edges_relationship_check CHECK (relationship IN
		('caused', 'followed_by', 'originated_from', 'targeted', 'associated_with', 'observed_on', 'related_to', 'enriched_by')),
	CONSTRAINT correlation_edges_provenance_check CHECK (provenance IN ('observed', 'inferred')),
	CONSTRAINT correlation_edges_confidence_check CHECK (confidence IN ('low', 'medium', 'high')),
	CONSTRAINT correlation_edges_evidence_not_blank CHECK (btrim(evidence) <> ''),
	CONSTRAINT correlation_edges_strategy_version_positive CHECK (strategy_version >= 1)
);

CREATE UNIQUE INDEX IF NOT EXISTS correlation_edges_unique
	ON correlation_edges (correlation_id, source_node_id, target_node_id, relationship, strategy_id);
CREATE INDEX IF NOT EXISTS correlation_edges_correlation_id_idx ON correlation_edges (correlation_id);
CREATE INDEX IF NOT EXISTS correlation_edges_source_node_idx ON correlation_edges (source_node_id);
CREATE INDEX IF NOT EXISTS correlation_edges_target_node_idx ON correlation_edges (target_node_id);
CREATE INDEX IF NOT EXISTS correlation_edges_strategy_id_idx ON correlation_edges (strategy_id);

-- attack_chains is a narrative summary of one correlation's graph
-- (phase12.md §40) — one chain per correlation.
CREATE TABLE IF NOT EXISTS attack_chains (
	id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	correlation_id UUID NOT NULL UNIQUE REFERENCES correlations (id) ON DELETE CASCADE,
	name           TEXT NOT NULL,
	description    TEXT NOT NULL DEFAULT '',
	confidence     TEXT NOT NULL,
	severity       TEXT NOT NULL,
	status         TEXT NOT NULL DEFAULT 'open',
	created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT attack_chains_confidence_check CHECK (confidence IN ('low', 'medium', 'high')),
	CONSTRAINT attack_chains_severity_check CHECK (severity IN ('informational', 'low', 'medium', 'high', 'critical')),
	CONSTRAINT attack_chains_status_check CHECK (status IN ('open', 'investigating', 'confirmed', 'resolved', 'dismissed')),
	CONSTRAINT attack_chains_name_not_blank CHECK (btrim(name) <> '')
);

-- attack_chain_stages holds each stage's evidence as a small JSONB array
-- of (node_type, reference_id) pairs (phase12.md §42) rather than a
-- seventh table — the same "opaque JSON for a small, append-only,
-- never-independently-queried structure" choice rule_versions.definition
-- makes for Phase 11's own Definition.
CREATE TABLE IF NOT EXISTS attack_chain_stages (
	id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	attack_chain_id UUID NOT NULL REFERENCES attack_chains (id) ON DELETE CASCADE,
	stage           TEXT NOT NULL,
	"order"         INT NOT NULL,
	confidence      TEXT NOT NULL,
	evidence        JSONB NOT NULL DEFAULT '[]',
	created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT attack_chain_stages_stage_check CHECK (stage IN
		('initial_activity', 'authentication', 'execution', 'privilege_change', 'persistence_signal',
		 'discovery_signal', 'network_activity', 'data_access', 'impact_signal')),
	CONSTRAINT attack_chain_stages_confidence_check CHECK (confidence IN ('low', 'medium', 'high'))
);

CREATE INDEX IF NOT EXISTS attack_chain_stages_chain_id_idx ON attack_chain_stages (attack_chain_id);
