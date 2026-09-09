package investigation

import (
	"context"
	"time"

	"github.com/google/uuid"

	domaininvestigation "ai-surface-platform/internal/domain/investigation"
	investigationrepo "ai-surface-platform/internal/repository/investigation"
	"ai-surface-platform/internal/repository/pagination"
)

// recordEvent appends one best-effort timeline/audit entry (phase9.md
// §61) — a failure here is logged, never propagated, since the
// investigation mutation it describes is already durably persisted by
// this point (the same "the record is safe, the audit trail is
// best-effort" discipline Phase 8 applies to finding_events).
func (s *Service) recordEvent(ctx context.Context, inv domaininvestigation.Investigation, eventType domaininvestigation.EventType, title, reason, actor string, sourceID *uuid.UUID) {
	if actor == "" {
		actor = "system"
	}
	metadata := map[string]any{}
	if reason != "" {
		metadata["reason"] = reason
	}
	e := domaininvestigation.TimelineEvent{
		TargetID: inv.TargetID, InvestigationID: inv.ID, Timestamp: time.Now().UTC(),
		Type: eventType, Title: title, Actor: actor, Metadata: metadata,
	}
	if sourceID != nil {
		e.SourceType = domaininvestigation.EntityInvestigation
		e.SourceID = sourceID
	}
	if err := e.Validate(); err != nil {
		s.logger.Error("investigation_timeline_event_invalid", "investigation_id", inv.ID, "error", err)
		return
	}
	if _, err := s.timeline.AppendEvent(ctx, e); err != nil {
		s.logger.Error("investigation_timeline_event_persist_failed", "investigation_id", inv.ID, "error", err)
	}
}

// Timeline returns a page of an investigation's timeline events
// (phase9.md §9/§11 — chronological by default; newestFirst reverses it).
func (s *Service) Timeline(ctx context.Context, investigationID uuid.UUID, newestFirst bool, p pagination.Params) (pagination.Page[domaininvestigation.TimelineEvent], error) {
	return s.timeline.ListTimeline(ctx, investigationrepo.TimelineListFilter{
		InvestigationID: investigationID, NewestFirst: newestFirst, Pagination: p,
	})
}
