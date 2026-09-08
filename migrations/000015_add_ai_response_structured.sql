-- Adds the structured (Observed/Inferred/Unknown/EvidenceGaps/NextSteps/
-- Questions/Citations) breakdown to ai_responses, alongside the already-
-- persisted flat `content`. Added for the REST API (internal/api) to
-- serve the AI Trust UI's real section-by-section breakdown instead of
-- only the rendered prose — internal/ai.StructuredResult is exactly what
-- every task already builds in memory (internal/ai/investigator.go); this
-- column just stops that structure from being discarded before it's
-- persisted. Additive, backward compatible: existing rows default to an
-- empty object, and no existing reader of ai_responses is affected.
ALTER TABLE ai_responses
	ADD COLUMN IF NOT EXISTS structured_result JSONB NOT NULL DEFAULT '{}'::jsonb;
