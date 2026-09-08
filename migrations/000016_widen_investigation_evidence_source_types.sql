-- Migration 000009 (Phase 9) defined investigation_evidence and
-- incident_cluster_items' source_type CHECK constraints against the
-- entity vocabulary that existed at the time: finding, asset, endpoint,
-- technology, scan, timeline_event, investigation. Phase 11 (rules/
-- alerts) and Phase 12 (correlations) later added detection_match,
-- alert, correlation, and attack_chain to
-- internal/domain/investigation.EntityType's validEntityTypes map (the
-- single source of truth for what an evidence/cluster-item reference may
-- point at), but the two CHECK constraints below were never widened to
-- match — first surfaced by a real "invocation.evidence_source_type_check
-- (SQLSTATE 23514)" failure the first time a detection match/alert was
-- ever promoted into an investigation against a live database (both
-- Service.PromoteToInvestigation and Service.AttachToInvestigation
-- attach a detection_match/alert-typed EvidenceRef). This migration
-- brings both constraints in line with EntityType.Valid(), not just
-- enough to fix the one failure observed.
ALTER TABLE investigation_evidence DROP CONSTRAINT investigation_evidence_source_type_check;
ALTER TABLE investigation_evidence ADD CONSTRAINT investigation_evidence_source_type_check CHECK (source_type IN (
	'finding', 'asset', 'endpoint', 'technology', 'scan', 'timeline_event', 'investigation',
	'detection_match', 'alert', 'correlation', 'attack_chain'
));

ALTER TABLE incident_cluster_items DROP CONSTRAINT incident_cluster_items_source_type_check;
ALTER TABLE incident_cluster_items ADD CONSTRAINT incident_cluster_items_source_type_check CHECK (source_type IN (
	'finding', 'asset', 'endpoint', 'technology', 'scan', 'timeline_event', 'investigation',
	'detection_match', 'alert', 'correlation', 'attack_chain'
));
