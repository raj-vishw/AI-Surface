import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCurrentTargetId } from "./useWorkspace";
import { listAISessions, getAISession, getSessionMessages, getSessionToolCalls, getSessionResult, sendMessage } from "@/api/ai";

export function useAISessions() {
  const targetId = useCurrentTargetId();
  return useQuery({
    queryKey: ["ai-sessions", targetId],
    queryFn: () => listAISessions(targetId!),
    enabled: !!targetId,
  });
}

export function useAISession(id: string | undefined) {
  return useQuery({ queryKey: ["ai-session", id], queryFn: () => getAISession(id!), enabled: !!id });
}

export function useSessionMessages(sessionId: string | undefined) {
  return useQuery({ queryKey: ["ai-messages", sessionId], queryFn: () => getSessionMessages(sessionId!), enabled: !!sessionId });
}

export function useSessionToolCalls(sessionId: string | undefined) {
  return useQuery({ queryKey: ["ai-tool-calls", sessionId], queryFn: () => getSessionToolCalls(sessionId!), enabled: !!sessionId });
}

export function useSessionResult(sessionId: string | undefined) {
  return useQuery({ queryKey: ["ai-result", sessionId], queryFn: () => getSessionResult(sessionId!), enabled: !!sessionId });
}

export function useSendMessage(sessionId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (content: string) => sendMessage(sessionId, content),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["ai-messages", sessionId] }),
  });
}
