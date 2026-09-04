-- Phase 9: investigation & incident correlation — see
-- internal/domain/investigation and
-- docs/architecture/investigation-engine.md.
--
-- investigations is the single analyst case-management entity (see
-- internal/domain/investigation's package doc comment for why a separate
-- "incidents" table was not introduced: an Incident's fields are a strict
-- subset of Investigation's, and phase9.md §54 explicitly sanctions this
-- consolidation). Never hard-deleted.
--
-- Every other table here references investigations.id (or, for
-- incident_clusters, targets.id directly, since a cluster may never be
-- accepted into an investigation).
--
-- SourceType/SourceID columns (investigation_evidence, timeline_events,
-- investigation_relationships, hypothesis_evidence, incident_cluster_items)
-- are deliberately polymorphic (finding/asset/endpoint/technology/scan/
-- timeline_event) and carry no foreign key of their own — a single FK
-- column cannot reference more than one target table, and adding one
-- nullable FK column per possible SourceType would multiply the schema
-- for no real safety benefit here (a stale reference is caught at read
-- time by the service layer's own not-found handling, exactly like
-- Phase 8's polymorphic EvidenceType keys already accept).
CREATE TABLE IF NOT EXISTS investigations (
	id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id         UUID NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
	title             TEXT NOT NULL,
	description       TEXT NOT NULL DEFAULT '',
	status            TEXT NOT NULL DEFAULT 'new',
	priority          TEXT NOT NULL DEFAULT '',
	severity          TEXT NOT NULL DEFAULT '',
	confidence        TEXT NOT NULL DEFAULT '',
	created_by        TEXT NOT NULL,
	assigned_to       TEXT NOT NULL DEFAULT '',
	detected_at       TIMESTAMPTZ,
	first_observed_at TIMESTAMPTZ,
	last_observed_at  TIMESTAMPTZ,
	version           INTEGER NOT NULL DEFAULT 1,
	created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
	closed_at         TIMESTAMPTZ,
	CONSTRAINT investigations_status_check CHECK (status IN ('new', 'open', 'investigating', 'contained', 'resolved', 'closed')),
	CONSTRAINT investigations_priority_check CHECK (priority IN ('', 'low', 'normal', 'high', 'urgent')),
	CONSTRAINT investigations_severity_check CHECK (severity IN ('', 'informational', 'low', 'medium', 'high', 'critical')),
	CONSTRAINT investigations_confidence_check CHECK (confidence IN ('', 'very_low', 'low', 'medium', 'high', 'very_high')),
	CONSTRAINT investigations_title_not_blank CHECK (btrim(title) <> ''),
	CONSTRAINT investigations_created_by_not_blank CHECK (btrim(created_by) <> '')
);

CREATE INDEX IF NOT EXISTS investigations_target_id_idx ON investigations (target_id);
CREATE INDEX IF NOT EXISTS investigations_status_idx ON investigations (status);
CREATE INDEX IF NOT EXISTS investigations_severity_idx ON investigations (severity);
CREATE INDEX IF NOT EXISTS investigations_assigned_to_idx ON investigations (assigned_to);

-- Evidence an investigation references — findings, assets, endpoints,
-- scans, or another investigation's own timeline events (phase9.md
-- §32-34). A reference, never a copy: no evidence content is duplicated
-- here, only provenance.
CREATE TABLE IF NOT EXISTS investigation_evidence (
	id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	investigation_id UUID NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
	source_type     TEXT NOT NULL,
	source_id       UUID NOT NULL,
	relation_type   TEXT NOT NULL DEFAULT '',
	observed_at     TIMESTAMPTZ NOT NULL,
	added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
	added_by        TEXT NOT NULL,
	created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT investigation_evidence_source_type_check CHECK (source_type IN ('finding', 'asset', 'endpoint', 'technology', 'scan', 'timeline_event', 'investigation')),
	CONSTRAINT investigation_evidence_relation_type_check CHECK (relation_type IN ('', 'related', 'correlated', 'suspected', 'confirmed')),
	CONSTRAINT investigation_evidence_added_by_not_blank CHECK (btrim(added_by) <> '')
);

-- One investigation never attaches the same underlying entity twice.
CREATE UNIQUE INDEX IF NOT EXISTS investigation_evidence_unique
	ON investigation_evidence (investigation_id, source_type, source_id);
CREATE INDEX IF NOT EXISTS investigation_evidence_investigation_id_idx ON investigation_evidence (investigation_id);
CREATE INDEX IF NOT EXISTS investigation_evidence_source_idx ON investigation_evidence (source_type, source_id);

-- An investigation's chronological narrative (phase9.md §9/§10), also
-- serving as its audit trail (phase9.md §61 — see the domain package's
-- doc comment for why a second, separate audit_log table was not added).
CREATE TABLE IF NOT EXISTS timeline_events (
	id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id       UUID NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
	investigation_id UUID NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
	"timestamp"     TIMESTAMPTZ NOT NULL,
	event_type      TEXT NOT NULL,
	source_type     TEXT NOT NULL DEFAULT '',
	source_id       UUID,
	title           TEXT NOT NULL,
	description     TEXT NOT NULL DEFAULT '',
	severity        TEXT NOT NULL DEFAULT '',
	actor           TEXT NOT NULL DEFAULT 'system',
	metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
	created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT timeline_events_title_not_blank CHECK (btrim(title) <> '')
);

CREATE INDEX IF NOT EXISTS timeline_events_investigation_id_idx ON timeline_events (investigation_id, "timestamp");
CREATE INDEX IF NOT EXISTS timeline_events_target_id_idx ON timeline_events (target_id);
CREATE INDEX IF NOT EXISTS timeline_events_type_idx ON timeline_events (event_type);

-- Correlation-engine (or analyst-created) edges between two entities
-- within one investigation (phase9.md §23). status distinguishes an
-- automatically-scored relationship that cleared the configured
-- threshold ('confirmed') from one that did not but is still surfaced to
-- an analyst as a near-miss ('candidate' — phase9.md §37).
CREATE TABLE IF NOT EXISTS investigation_relationships (
	id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	investigation_id  UUID NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
	source_type       TEXT NOT NULL,
	source_id         UUID NOT NULL,
	target_type       TEXT NOT NULL,
	target_id         UUID NOT NULL,
	relationship_type TEXT NOT NULL,
	status            TEXT NOT NULL DEFAULT 'candidate',
	score             INTEGER NOT NULL DEFAULT 0,
	confidence        TEXT NOT NULL DEFAULT '',
	explanation       TEXT NOT NULL,
	signals           JSONB NOT NULL DEFAULT '{}'::jsonb,
	rule_id           TEXT NOT NULL,
	rule_version      INTEGER NOT NULL DEFAULT 1,
	created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT investigation_relationships_status_check CHECK (status IN ('candidate', 'confirmed')),
	CONSTRAINT investigation_relationships_explanation_not_blank CHECK (btrim(explanation) <> ''),
	CONSTRAINT investigation_relationships_rule_id_not_blank CHECK (btrim(rule_id) <> '')
);

-- Re-running correlation over unchanged data is idempotent — the same
-- rule producing the same edge again updates the existing row rather
-- than duplicating it.
CREATE UNIQUE INDEX IF NOT EXISTS investigation_relationships_unique
	ON investigation_relationships (investigation_id, source_type, source_id, target_type, target_id, relationship_type, rule_id);
CREATE INDEX IF NOT EXISTS investigation_relationships_investigation_id_idx ON investigation_relationships (investigation_id);

CREATE TABLE IF NOT EXISTS hypotheses (
	id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	investigation_id UUID NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
	title            TEXT NOT NULL,
	description      TEXT NOT NULL DEFAULT '',
	status           TEXT NOT NULL DEFAULT 'proposed',
	confidence       TEXT NOT NULL DEFAULT '',
	created_by       TEXT NOT NULL,
	created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT hypotheses_status_check CHECK (status IN ('proposed', 'investigating', 'supported', 'unsupported', 'confirmed', 'rejected')),
	CONSTRAINT hypotheses_title_not_blank CHECK (btrim(title) <> '')
);

CREATE INDEX IF NOT EXISTS hypotheses_investigation_id_idx ON hypotheses (investigation_id);

-- Append-only — a hypothesis's supporting/refuting evidence is never
-- edited or removed, only added to.
CREATE TABLE IF NOT EXISTS hypothesis_evidence (
	id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	hypothesis_id UUID NOT NULL REFERENCES hypotheses (id) ON DELETE CASCADE,
	source_type   TEXT NOT NULL,
	source_id     UUID NOT NULL,
	description   TEXT NOT NULL,
	observed_at   TIMESTAMPTZ,
	created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT hypothesis_evidence_description_not_blank CHECK (btrim(description) <> '')
);

CREATE INDEX IF NOT EXISTS hypothesis_evidence_hypothesis_id_idx ON hypothesis_evidence (hypothesis_id);

-- Append-only — see internal/domain/investigation.Note's doc comment for
-- why there is no update path.
CREATE TABLE IF NOT EXISTS investigation_notes (
	id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	investigation_id UUID NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
	author_id        TEXT NOT NULL,
	content          TEXT NOT NULL,
	created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT investigation_notes_content_not_blank CHECK (btrim(content) <> '')
);

CREATE INDEX IF NOT EXISTS investigation_notes_investigation_id_idx ON investigation_notes (investigation_id);

-- System-suggested groupings (phase9.md §41) — never auto-merged into an
-- investigation; an analyst explicitly accepts or rejects one. Rejected
-- clusters are preserved, never deleted.
CREATE TABLE IF NOT EXISTS incident_clusters (
	id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id                 UUID NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
	title                     TEXT NOT NULL,
	confidence                TEXT NOT NULL DEFAULT '',
	status                    TEXT NOT NULL DEFAULT 'suggested',
	accepted_investigation_id UUID REFERENCES investigations (id) ON DELETE SET NULL,
	created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT incident_clusters_status_check CHECK (status IN ('suggested', 'accepted', 'rejected')),
	CONSTRAINT incident_clusters_title_not_blank CHECK (btrim(title) <> '')
);

CREATE INDEX IF NOT EXISTS incident_clusters_target_id_idx ON incident_clusters (target_id);
CREATE INDEX IF NOT EXISTS incident_clusters_status_idx ON incident_clusters (status);

CREATE TABLE IF NOT EXISTS incident_cluster_items (
	id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	cluster_id UUID NOT NULL REFERENCES incident_clusters (id) ON DELETE CASCADE,
	source_type TEXT NOT NULL,
	source_id  UUID NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT incident_cluster_items_source_type_check CHECK (source_type IN ('finding', 'asset', 'endpoint', 'technology', 'scan', 'timeline_event', 'investigation'))
);

CREATE UNIQUE INDEX IF NOT EXISTS incident_cluster_items_unique ON incident_cluster_items (cluster_id, source_type, source_id);
CREATE INDEX IF NOT EXISTS incident_cluster_items_cluster_id_idx ON incident_cluster_items (cluster_id);
