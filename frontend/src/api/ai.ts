/** Proposed REST contract: GET/POST /api/v1/ai/sessions, GET /:id/
 * messages, POST /:id/messages, GET /:id/tool-calls — maps to `ai-recon
 * ai session|chat|note` (Phase 13). */
import { USE_MOCKS, mockDelay } from "./config";
import { apiRequest } from "./client";
import {
  aiSessions as mockSessions,
  aiMessages as mockMessages,
  aiToolCalls as mockToolCalls,
  aiResults as mockResults,
} from "@/mocks/database";
import { mockId } from "@/mocks/random";
import type { AISession, AIMessage, AIToolCall, AIResult } from "@/types/ai";

export async function listAISessions(targetId: string): Promise<AISession[]> {
  if (USE_MOCKS) return mockDelay(mockSessions.filter((s) => s.targetId === targetId));
  return apiRequest<AISession[]>("/api/v1/ai/sessions", { searchParams: { target_id: targetId } });
}

export async function getAISession(id: string): Promise<AISession | undefined> {
  if (USE_MOCKS) return mockDelay(mockSessions.find((s) => s.id === id));
  return apiRequest<AISession>(`/api/v1/ai/sessions/${id}`);
}

export async function getSessionMessages(sessionId: string): Promise<AIMessage[]> {
  if (USE_MOCKS) return mockDelay(mockMessages.filter((m) => m.sessionId === sessionId));
  return apiRequest<AIMessage[]>(`/api/v1/ai/sessions/${sessionId}/messages`);
}

export async function getSessionToolCalls(sessionId: string): Promise<AIToolCall[]> {
  if (USE_MOCKS) return mockDelay(mockToolCalls.filter((t) => t.sessionId === sessionId));
  return apiRequest<AIToolCall[]>(`/api/v1/ai/sessions/${sessionId}/tool-calls`);
}

export async function getSessionResult(sessionId: string): Promise<AIResult | undefined> {
  if (USE_MOCKS) return mockDelay(mockResults.find((r) => r.sessionId === sessionId));
  return apiRequest<AIResult>(`/api/v1/ai/sessions/${sessionId}/result`);
}

/** Sends a new user message and returns the (mock) assistant reply — the
 * mock reply politely declines to be treated as a real backend, since
 * this platform's real AI provider requires ai.enabled=true server-side
 * (disabled by default — see docs/ai/safety.md) and this is a frontend-
 * only mock. */
export async function sendMessage(sessionId: string, content: string): Promise<AIMessage> {
  const userMsg: AIMessage = { id: mockId("msg"), sessionId, role: "user", content, createdAt: new Date().toISOString() };
  if (USE_MOCKS) {
    mockMessages.push(userMsg);
    const reply: AIMessage = {
      id: mockId("msg"),
      sessionId,
      role: "assistant",
      content: "This is a development-mode mock reply — connect a real AI provider and backend endpoint to get a live, evidence-grounded response.",
      createdAt: new Date().toISOString(),
    };
    mockMessages.push(reply);
    return mockDelay(reply, 600);
  }
  return apiRequest<AIMessage>(`/api/v1/ai/sessions/${sessionId}/messages`, { method: "POST", body: { content } });
}
