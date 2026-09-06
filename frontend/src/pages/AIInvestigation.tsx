import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { BrainCircuit, Send, Wrench, AlertTriangle } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { EmptyState } from "@/components/common/EmptyState";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Skeleton } from "@/components/ui/Skeleton";
import { Badge } from "@/components/ui/Badge";
import { StructuredResultView } from "@/components/ai/StructuredResultView";
import { useAISessions, useSessionMessages, useSessionToolCalls, useSessionResult, useSendMessage } from "@/hooks/useAI";
import { useInvestigation } from "@/hooks/useInvestigations";
import { cn, formatRelativeTime } from "@/lib/utils";

export default function AIInvestigation() {
  const { sessionId: paramSessionId } = useParams<{ sessionId: string }>();
  const navigate = useNavigate();
  const { data: sessions, isLoading: sessionsLoading } = useAISessions();
  const [draft, setDraft] = useState("");

  const sessionId = paramSessionId ?? sessions?.[0]?.id;
  const { data: investigation } = useInvestigation(sessions?.find((s) => s.id === sessionId)?.investigationId ?? undefined);
  const { data: messages } = useSessionMessages(sessionId);
  const { data: toolCalls } = useSessionToolCalls(sessionId);
  const { data: result, isLoading: resultLoading } = useSessionResult(sessionId);
  const sendMessage = useSendMessage(sessionId ?? "");

  useEffect(() => {
    if (!paramSessionId && sessions?.[0]) navigate(`/ai/${sessions[0].id}`, { replace: true });
  }, [paramSessionId, sessions, navigate]);

  if (sessionsLoading) {
    return (
      <div className="p-6">
        <Skeleton className="h-96" />
      </div>
    );
  }

  if (!sessions || sessions.length === 0) {
    return (
      <div>
        <PageHeader title="AI Investigation" />
        <EmptyState
          icon={BrainCircuit}
          title="No AI sessions yet"
          description="Start an AI-assisted investigation from any investigation's detail page to begin."
        />
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="AI Investigation"
        description={investigation ? investigation.title : "Select a session"}
      />

      <div className="grid grid-cols-1 gap-4 p-6 lg:grid-cols-[220px_1.3fr_1fr]">
        {/* Session list */}
        <Card className="h-fit">
          <CardHeader>
            <CardTitle>Sessions</CardTitle>
          </CardHeader>
          <ul className="divide-y divide-[color:var(--color-border)]">
            {sessions.map((s) => (
              <li key={s.id}>
                <button
                  onClick={() => navigate(`/ai/${s.id}`)}
                  className={cn(
                    "block w-full px-3 py-2.5 text-left text-xs hover:bg-[color:var(--color-surface-hover)]",
                    s.id === sessionId && "bg-[color:var(--color-accent-muted)] text-[color:var(--color-accent-strong)]",
                  )}
                >
                  Session {s.id.slice(0, 8)}
                  <p className="text-[0.65rem] text-[color:var(--color-text-faint)]">{formatRelativeTime(s.updatedAt)}</p>
                </button>
              </li>
            ))}
          </ul>
        </Card>

        {/* AI Analysis */}
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>AI Analysis</CardTitle>
              {result && <Badge variant="outline">{result.confidence} confidence</Badge>}
            </CardHeader>
            <CardContent>
              {resultLoading ? (
                <Skeleton className="h-40" />
              ) : result ? (
                <>
                  <StructuredResultView result={result.structured} />
                  {result.fabricatedCitationsRemoved.length > 0 && (
                    <p className="mt-4 flex items-center gap-1.5 rounded-md border border-[color:var(--color-warning)]/30 bg-[color:var(--color-warning-muted)] px-2.5 py-1.5 text-xs text-[color:var(--color-warning)]">
                      <AlertTriangle className="size-3.5" /> {result.fabricatedCitationsRemoved.length} unsupported citation(s) were automatically removed from this response.
                    </p>
                  )}
                </>
              ) : (
                <p className="text-sm text-[color:var(--color-text-muted)]">No analysis generated for this session yet.</p>
              )}
            </CardContent>
          </Card>

          {toolCalls && toolCalls.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Tool Calls</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-wrap gap-2">
                {toolCalls.map((call) => (
                  <span
                    key={call.id}
                    className="flex items-center gap-1.5 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-surface-elevated)] px-2 py-1 text-xs text-[color:var(--color-text-muted)]"
                    title={call.resultSummary}
                  >
                    <Wrench className="size-3" />
                    {call.tool.replace(/_/g, " ")}
                    <span className={call.resultStatus === "success" ? "text-[color:var(--color-success)]" : call.resultStatus === "empty" ? "text-[color:var(--color-text-faint)]" : "text-[color:var(--color-danger)]"}>
                      ●
                    </span>
                  </span>
                ))}
              </CardContent>
            </Card>
          )}
        </div>

        {/* Analyst Conversation */}
        <Card className="flex h-[36rem] flex-col">
          <CardHeader>
            <CardTitle>Analyst Conversation</CardTitle>
          </CardHeader>
          <div className="flex-1 space-y-3 overflow-y-auto p-4">
            {(!messages || messages.length === 0) && (
              <p className="text-sm text-[color:var(--color-text-muted)]">Ask a question about this investigation to begin.</p>
            )}
            {messages?.map((m) => (
              <div key={m.id} className={cn("max-w-[85%] rounded-lg px-3 py-2 text-sm", m.role === "user" ? "ml-auto bg-[color:var(--color-accent-muted)] text-[color:var(--color-text)]" : "bg-[color:var(--color-surface-elevated)] text-[color:var(--color-text)]")}>
                {m.content}
              </div>
            ))}
          </div>
          <form
            className="flex items-center gap-2 border-t border-[color:var(--color-border)] p-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (!draft.trim() || !sessionId) return;
              sendMessage.mutate(draft);
              setDraft("");
            }}
          >
            <Input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="Ask about evidence, next steps..."
              disabled={!sessionId || sendMessage.isPending}
            />
            <Button type="submit" size="icon" disabled={!draft.trim() || sendMessage.isPending}>
              <Send className="size-4" />
            </Button>
          </form>
        </Card>
      </div>
    </div>
  );
}
