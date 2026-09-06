-- Phase 14: security analytics, dashboards, and reporting
-- (internal/analytics, internal/domain/reporting, internal/reporting).
--
-- No new tables are needed for analytics itself — internal/repository/
-- analytics aggregates existing tables (assets, findings, alerts,
-- detection_matches, correlations, attack_chains, investigations,
-- intelligence_records, risk_scores, ai_requests/ai_responses/
-- ai_tool_calls) read-only; see that package's own doc comment.
--
-- reports mirrors rule_versions' exact versioning pattern (phase14.md
-- §77: "regenerating a report should create a new report version... do
-- not overwrite the original") — one (target_id, report_type,
-- subject_id) triple's reports form a version sequence, never updated
-- once created except by Approve, which only ever touches the
-- approval_* columns.
CREATE TABLE IF NOT EXISTS reports (
	id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id      UUID NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
	report_type    TEXT NOT NULL,
	-- subject_id is the investigation/asset/correlation id this report
	-- concerns; NULL for target-wide reports (attack_surface, executive,
	-- audit, compliance). No FK: it is deliberately polymorphic
	-- (investigations/assets/correlations), the same "one column cannot
	-- reference more than one target table" reasoning
	-- investigation_evidence's source_id already documents.
	subject_id     UUID,
	version        INTEGER NOT NULL,
	title          TEXT NOT NULL,
	content        JSONB NOT NULL,
	status         TEXT NOT NULL DEFAULT 'generated',
	content_hash   CHAR(64) NOT NULL,
	generated_by   TEXT NOT NULL,
	generated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
	provider       TEXT,
	model          TEXT,
	prompt_version TEXT,
	approved_by    TEXT,
	approved_at    TIMESTAMPTZ,
	approval_notes TEXT NOT NULL DEFAULT '',
	created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT reports_type_check CHECK (report_type IN (
		'investigation', 'asset', 'attack_surface', 'detection', 'correlation', 'executive', 'audit', 'compliance'
	)),
	CONSTRAINT reports_status_check CHECK (status IN ('draft', 'generated', 'reviewed', 'approved')),
	CONSTRAINT reports_version_positive CHECK (version >= 1),
	CONSTRAINT reports_title_not_blank CHECK (btrim(title) <> ''),
	CONSTRAINT reports_generated_by_not_blank CHECK (btrim(generated_by) <> ''),
	CONSTRAINT reports_approved_requires_actor CHECK (status <> 'approved' OR approved_by IS NOT NULL)
);

-- One version sequence per (target, type, subject) — NULLS NOT DISTINCT
-- so target-wide report types (subject_id IS NULL) are also deduplicated
-- correctly rather than every NULL comparing as distinct.
CREATE UNIQUE INDEX IF NOT EXISTS reports_version_unique
	ON reports (target_id, report_type, subject_id, version) NULLS NOT DISTINCT;
CREATE INDEX IF NOT EXISTS reports_target_id_idx ON reports (target_id);
CREATE INDEX IF NOT EXISTS reports_report_type_idx ON reports (report_type);
CREATE INDEX IF NOT EXISTS reports_status_idx ON reports (status);
CREATE INDEX IF NOT EXISTS reports_subject_id_idx ON reports (subject_id);
CREATE INDEX IF NOT EXISTS reports_created_at_idx ON reports (created_at, id);

-- Evidence packages (phase14.md §45) — always scoped to one report,
-- never a dump of an entire target's data.
CREATE TABLE IF NOT EXISTS evidence_packages (
	id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id  UUID NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
	report_id  UUID REFERENCES reports (id) ON DELETE SET NULL,
	created_by TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT evidence_packages_created_by_not_blank CHECK (btrim(created_by) <> '')
);

CREATE INDEX IF NOT EXISTS evidence_packages_target_id_idx ON evidence_packages (target_id);
CREATE INDEX IF NOT EXISTS evidence_packages_report_id_idx ON evidence_packages (report_id);
CREATE INDEX IF NOT EXISTS evidence_packages_created_at_idx ON evidence_packages (created_at, id);

-- Evidence manifest entries (phase14.md §46/§47) — a reference plus an
-- integrity hash, never a copy of the referenced row's own content.
CREATE TABLE IF NOT EXISTS evidence_items (
	id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	package_id   UUID NOT NULL REFERENCES evidence_packages (id) ON DELETE CASCADE,
	item_type    TEXT NOT NULL,
	reference_id UUID NOT NULL,
	hash         CHAR(64) NOT NULL,
	"timestamp"  TIMESTAMPTZ NOT NULL,
	created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT evidence_items_type_check CHECK (item_type IN (
		'finding', 'alert', 'detection_match', 'correlation', 'investigation', 'intelligence_record', 'asset', 'event'
	))
);

CREATE INDEX IF NOT EXISTS evidence_items_package_id_idx ON evidence_items (package_id);

-- Generic, framework-agnostic control evidence (phase14.md §50) — no
-- compliance framework is hard-coded (none already exists in this
-- project); control_id is an analyst-supplied grouping key only.
CREATE TABLE IF NOT EXISTS control_evidence (
	id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id     UUID NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
	control_id    TEXT NOT NULL,
	evidence_type TEXT NOT NULL,
	reference_id  UUID NOT NULL,
	description   TEXT NOT NULL,
	collected_at  TIMESTAMPTZ NOT NULL,
	created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT control_evidence_type_check CHECK (evidence_type IN (
		'finding', 'alert', 'detection_match', 'correlation', 'investigation', 'intelligence_record', 'asset', 'event'
	)),
	CONSTRAINT control_evidence_control_id_not_blank CHECK (btrim(control_id) <> ''),
	CONSTRAINT control_evidence_description_not_blank CHECK (btrim(description) <> '')
);

CREATE INDEX IF NOT EXISTS control_evidence_target_id_idx ON control_evidence (target_id);
CREATE INDEX IF NOT EXISTS control_evidence_control_id_idx ON control_evidence (control_id);
CREATE INDEX IF NOT EXISTS control_evidence_collected_at_idx ON control_evidence (collected_at);

-- Minimal, generic dashboard filter persistence (phase14.md §23) — this
-- platform has no user-preference system to extend, so this is the
-- smallest table that satisfies "analysts can save dashboard filters":
-- one named, user-scoped filter set per target.
CREATE TABLE IF NOT EXISTS dashboard_preferences (
	id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id  UUID NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
	user_id    TEXT NOT NULL,
	name       TEXT NOT NULL,
	filters    JSONB NOT NULL DEFAULT '{}'::jsonb,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT dashboard_preferences_user_id_not_blank CHECK (btrim(user_id) <> ''),
	CONSTRAINT dashboard_preferences_name_not_blank CHECK (btrim(name) <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS dashboard_preferences_unique ON dashboard_preferences (target_id, user_id, name);
