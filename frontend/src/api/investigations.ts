/** Proposed REST contract: GET /api/v1/investigations, GET /:id,
 * GET /:id/timeline, GET /:id/notes, GET /:id/hypotheses — maps to
 * `ai-recon investigate list|show|timeline|note|hypothesis`. */
import { USE_MOCKS, mockDelay } from "./config";
import { apiRequest } from "./client";
import { mockPage } from "@/mocks/paginate";
import {
  investigations as mockInvestigations,
  timelineEvents as mockTimeline,
  notes as mockNotes,
  hypotheses as mockHypotheses,
} from "@/mocks/database";
import type {
  Investigation,
  InvestigationStatus,
  TimelineEvent,
  InvestigationNote,
  Hypothesis,
} from "@/types/investigation";
import type { Page, PageParams } from "@/types/common";

export interface InvestigationFilters {
  status?: InvestigationStatus;
}

export async function listInvestigations(
  targetId: string,
  filters: InvestigationFilters = {},
  page?: PageParams,
): Promise<Page<Investigation>> {
  if (USE_MOCKS) {
    let items = mockInvestigations.filter((i) => i.targetId === targetId);
    if (filters.status) items = items.filter((i) => i.status === filters.status);
    items = [...items].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    return mockPage(items, page);
  }
  return apiRequest<Page<Investigation>>("/api/v1/investigations", {
    searchParams: { target_id: targetId, ...filters, limit: page?.limit, cursor: page?.cursor },
  });
}

export async function getInvestigation(id: string): Promise<Investigation | undefined> {
  if (USE_MOCKS) return mockDelay(mockInvestigations.find((i) => i.id === id));
  return apiRequest<Investigation>(`/api/v1/investigations/${id}`);
}

export async function getInvestigationTimeline(id: string): Promise<TimelineEvent[]> {
  if (USE_MOCKS) {
    return mockDelay(
      mockTimeline.filter((t) => t.investigationId === id).sort((a, b) => a.timestamp.localeCompare(b.timestamp)),
    );
  }
  return apiRequest<TimelineEvent[]>(`/api/v1/investigations/${id}/timeline`);
}

export async function getInvestigationNotes(id: string): Promise<InvestigationNote[]> {
  if (USE_MOCKS) return mockDelay(mockNotes.filter((n) => n.investigationId === id));
  return apiRequest<InvestigationNote[]>(`/api/v1/investigations/${id}/notes`);
}

export async function getInvestigationHypotheses(id: string): Promise<Hypothesis[]> {
  if (USE_MOCKS) return mockDelay(mockHypotheses.filter((h) => h.investigationId === id));
  return apiRequest<Hypothesis[]>(`/api/v1/investigations/${id}/hypotheses`);
}
