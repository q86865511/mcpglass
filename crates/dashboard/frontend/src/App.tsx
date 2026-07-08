import { useCallback, useEffect, useRef, useState } from "react";
import type { Direction, MessagesResponse, SessionStats, SessionSummary } from "./api";
import {
  fetchMessages,
  fetchSessionStats,
  fetchSessions,
} from "./api";
import { Sidebar } from "./components/Sidebar";
import { Toolbar } from "./components/Toolbar";
import { MessageTable } from "./components/MessageTable";
import { DetailPanel } from "./components/DetailPanel";
import { StatsBar } from "./components/StatsBar";
import { Pagination } from "./components/Pagination";

const PAGE_SIZE = 100;
const AUTO_REFRESH_MS = 2000;

export function App() {
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [sessionsError, setSessionsError] = useState<string | null>(null);
  const [selectedSessionId, setSelectedSessionId] = useState<number | null>(null);

  const [direction, setDirection] = useState<Direction | "">("");
  const [method, setMethod] = useState("");
  const [query, setQuery] = useState("");
  const [offset, setOffset] = useState(0);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const [messagesResp, setMessagesResp] = useState<MessagesResponse | null>(null);
  const [messagesError, setMessagesError] = useState<string | null>(null);
  const [selectedMessageId, setSelectedMessageId] = useState<number | null>(null);

  const [stats, setStats] = useState<SessionStats | null>(null);

  // Monotonic request counters so a slow, stale response (e.g. from a
  // session we've since navigated away from) can't clobber a newer one.
  const messagesSeqRef = useRef(0);
  const statsSeqRef = useRef(0);

  // Reset paging/selection when switching sessions or changing filters.
  useEffect(() => {
    setOffset(0);
    setSelectedMessageId(null);
  }, [selectedSessionId, direction, method, query]);

  const loadSessions = useCallback(() => {
    fetchSessions()
      .then((r) => {
        setSessions(r.sessions);
        setSessionsError(null);
        setSelectedSessionId((cur) => {
          if (cur !== null && r.sessions.some((s) => s.id === cur)) return cur;
          return r.sessions[0]?.id ?? null;
        });
      })
      .catch((e: unknown) => setSessionsError(e instanceof Error ? e.message : String(e)));
  }, []);

  const loadMessages = useCallback(() => {
    if (selectedSessionId === null) {
      messagesSeqRef.current += 1;
      setMessagesResp(null);
      return;
    }
    const seq = ++messagesSeqRef.current;
    fetchMessages(selectedSessionId, {
      limit: PAGE_SIZE,
      offset,
      direction,
      method: method.trim(),
      q: query.trim(),
    })
      .then((r) => {
        if (messagesSeqRef.current !== seq) return; // superseded by a newer request
        setMessagesResp(r);
        setMessagesError(null);
      })
      .catch((e: unknown) => {
        if (messagesSeqRef.current !== seq) return;
        setMessagesError(e instanceof Error ? e.message : String(e));
      });
  }, [selectedSessionId, offset, direction, method, query]);

  const loadStats = useCallback(() => {
    if (selectedSessionId === null) {
      statsSeqRef.current += 1;
      setStats(null);
      return;
    }
    const seq = ++statsSeqRef.current;
    fetchSessionStats(selectedSessionId)
      .then((r) => {
        if (statsSeqRef.current !== seq) return; // superseded by a newer request
        setStats(r);
      })
      .catch(() => {
        if (statsSeqRef.current !== seq) return;
        setStats(null);
      });
  }, [selectedSessionId]);

  useEffect(() => {
    loadSessions();
  }, [loadSessions]);

  useEffect(() => {
    loadMessages();
  }, [loadMessages]);

  useEffect(() => {
    loadStats();
  }, [loadStats]);

  const autoRefreshRef = useRef({ loadSessions, loadMessages, loadStats });
  autoRefreshRef.current = { loadSessions, loadMessages, loadStats };

  useEffect(() => {
    if (!autoRefresh) return;
    const id = setInterval(() => {
      autoRefreshRef.current.loadSessions();
      autoRefreshRef.current.loadMessages();
      autoRefreshRef.current.loadStats();
    }, AUTO_REFRESH_MS);
    return () => clearInterval(id);
  }, [autoRefresh]);

  const hasNoSessions = sessions.length === 0 && !sessionsError;

  return (
    <div className="app">
      <Sidebar
        sessions={sessions}
        selectedId={selectedSessionId}
        onSelect={setSelectedSessionId}
      />
      <main className="main">
        {sessionsError && <div className="banner banner-error">Failed to load sessions: {sessionsError}</div>}
        {hasNoSessions ? (
          <div className="empty-state">
            <h2>No sessions yet</h2>
            <p>Wrap an MCP server command with mcpglass to start capturing traffic:</p>
            <pre className="mono empty-state-cmd">mcpglass wrap -- &lt;your mcp server command&gt;</pre>
          </div>
        ) : (
          <>
            <StatsBar stats={stats} />
            <Toolbar
              direction={direction}
              onDirectionChange={setDirection}
              method={method}
              onMethodChange={setMethod}
              query={query}
              onQueryChange={setQuery}
              autoRefresh={autoRefresh}
              onAutoRefreshChange={setAutoRefresh}
            />
            {messagesError && <div className="banner banner-error">Failed to load messages: {messagesError}</div>}
            <div className="content-split">
              <div className="table-pane">
                <MessageTable
                  messages={messagesResp?.messages ?? []}
                  selectedId={selectedMessageId}
                  onSelect={setSelectedMessageId}
                />
                <Pagination
                  offset={offset}
                  limit={PAGE_SIZE}
                  total={messagesResp?.total ?? 0}
                  onOffsetChange={setOffset}
                />
              </div>
              <DetailPanel messageId={selectedMessageId} />
            </div>
          </>
        )}
      </main>
    </div>
  );
}
