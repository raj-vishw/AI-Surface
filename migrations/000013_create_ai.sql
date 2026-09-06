-- Phase 13: AI-assisted investigation copilot (internal/domain/ai).
--
-- Five new tables — ai_sessions, ai_messages, ai_requests, ai_responses,
-- ai_tool_calls — together constitute this phase's complete audit trail
-- (phase13.md §34/§53/§113): every AI operation and every tool
-- invocation this platform ever performs is reconstructible from these
-- rows. No separate generic "audit_log" table is introduced — the same
-- "these ARE the audit trail" discipline investigation_timeline_events
-- already established for Phase 9-12's own audit requirements.
--
-- No ai_jobs table: this platform has no job/worker queue yet (see
-- cmd/worker's own doc comment, unchanged since Phase 1) — AI requests
-- run synchronously from the CLI, bounded by a context timeout. Adding a
-- queued/running/completed status table with nothing to actually
-- transition it would be exactly the kind of fabricated infrastructure
-- phase12.md's own precedent (no correlation worker pool) already
-- rejected.
--
-- investigation_notes gains three additive columns rather than a
-- separate ai_notes table (phase13.md §113's own "do not create
-- duplicate audit tables" applies equally to duplicating the note model
-- itself) — an AI-drafted note IS an investigation.Note, just one
-- flagged ai_generated until an analyst explicitly approves it
-- (phase13.md §44/§45).

CREATE TABLE IF NOT EXISTS ai_sessions (
	id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id        UUID NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
	investigation_id UUID REFERENCES investigations (id) ON DELETE CASCADE,
	user_id          TEXT NOT NULL,
	created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT ai_sessions_user_id_not_blank CHECK (btrim(user_id) <> '')
);

CREATE INDEX IF NOT EXISTS ai_sessions_target_id_idx ON ai_sessions (target_id);
CREATE INDEX IF NOT EXISTS ai_sessions_investigation_id_idx ON ai_sessions (investigation_id);
CREATE INDEX IF NOT EXISTS ai_sessions_user_id_idx ON ai_sessions (user_id);
CREATE INDEX IF NOT EXISTS ai_sessions_created_at_idx ON ai_sessions (created_at, id);

CREATE TABLE IF NOT EXISTS ai_messages (
	id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	session_id UUID NOT NULL REFERENCES ai_sessions (id) ON DELETE CASCADE,
	role       TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
	content    TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT ai_messages_content_not_blank CHECK (btrim(content) <> '')
);

CREATE INDEX IF NOT EXISTS ai_messages_session_id_idx ON ai_messages (session_id, created_at);

CREATE TABLE IF NOT EXISTS ai_requests (
	id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	target_id        UUID NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
	session_id       UUID REFERENCES ai_sessions (id) ON DELETE SET NULL,
	investigation_id UUID REFERENCES investigations (id) ON DELETE SET NULL,
	user_id          TEXT NOT NULL,
	task_type        TEXT NOT NULL,
	instructions     TEXT NOT NULL DEFAULT '',
	prompt_version   TEXT NOT NULL,
	context_hash     TEXT NOT NULL,
	created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT ai_requests_user_id_not_blank CHECK (btrim(user_id) <> ''),
	CONSTRAINT ai_requests_prompt_version_not_blank CHECK (btrim(prompt_version) <> ''),
	CONSTRAINT ai_requests_context_hash_not_blank CHECK (btrim(context_hash) <> '')
);

CREATE INDEX IF NOT EXISTS ai_requests_target_id_idx ON ai_requests (target_id);
CREATE INDEX IF NOT EXISTS ai_requests_investigation_id_idx ON ai_requests (investigation_id);
CREATE INDEX IF NOT EXISTS ai_requests_session_id_idx ON ai_requests (session_id);
CREATE INDEX IF NOT EXISTS ai_requests_user_id_idx ON ai_requests (user_id);
CREATE INDEX IF NOT EXISTS ai_requests_created_at_idx ON ai_requests (created_at, id);

CREATE TABLE IF NOT EXISTS ai_responses (
	id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	request_id     UUID NOT NULL UNIQUE REFERENCES ai_requests (id) ON DELETE CASCADE,
	content        TEXT NOT NULL,
	model          TEXT NOT NULL,
	provider       TEXT NOT NULL,
	prompt_version TEXT NOT NULL,
	confidence     TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
	citations      JSONB NOT NULL DEFAULT '[]'::jsonb,
	response_hash  TEXT NOT NULL,
	input_tokens   INTEGER NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
	output_tokens  INTEGER NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
	latency_ms     BIGINT NOT NULL DEFAULT 0 CHECK (latency_ms >= 0),
	created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT ai_responses_content_not_blank CHECK (btrim(content) <> '')
);

CREATE INDEX IF NOT EXISTS ai_responses_created_at_idx ON ai_responses (created_at, id);

CREATE TABLE IF NOT EXISTS ai_tool_calls (
	id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	session_id     UUID REFERENCES ai_sessions (id) ON DELETE SET NULL,
	request_id     UUID REFERENCES ai_requests (id) ON DELETE SET NULL,
	target_id      UUID NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
	user_id        TEXT NOT NULL,
	tool           TEXT NOT NULL,
	arguments      JSONB NOT NULL DEFAULT '{}'::jsonb,
	result_status  TEXT NOT NULL CHECK (result_status IN ('success', 'error', 'denied')),
	result_summary TEXT NOT NULL DEFAULT '',
	error          TEXT NOT NULL DEFAULT '',
	created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT ai_tool_calls_user_id_not_blank CHECK (btrim(user_id) <> ''),
	CONSTRAINT ai_tool_calls_tool_not_blank CHECK (btrim(tool) <> '')
);

CREATE INDEX IF NOT EXISTS ai_tool_calls_target_id_idx ON ai_tool_calls (target_id);
CREATE INDEX IF NOT EXISTS ai_tool_calls_session_id_idx ON ai_tool_calls (session_id);
CREATE INDEX IF NOT EXISTS ai_tool_calls_created_at_idx ON ai_tool_calls (created_at, id);
CREATE INDEX IF NOT EXISTS ai_tool_calls_result_status_idx ON ai_tool_calls (result_status);

-- Additive investigation_notes columns (phase13.md §44/§45) — an
-- AI-generated note's own Content is still immutable once created (the
-- discipline internal/domain/investigation.Note's doc comment
-- documents); approved_by/approved_at are the one deliberate, narrow
-- exception, recording an analyst's explicit approval without ever
-- rewriting what the note actually says.
ALTER TABLE investigation_notes ADD COLUMN IF NOT EXISTS ai_generated BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE investigation_notes ADD COLUMN IF NOT EXISTS approved_by TEXT;
ALTER TABLE investigation_notes ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;
