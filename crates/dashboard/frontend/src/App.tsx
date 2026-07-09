import { useCallback, useEffect, useRef, useState } from "react";
import type {
  ContextReport,
  Direction,
  InjectCounts,
  InjectEventsResponse,
  MessagesResponse,
  SecurityCounts,
  SecurityEventsResponse,
  SessionStats,
  SessionSummary,
} from "./api";
import {
  fetchContext,
  fetchInjectCounts,
  fetchInjectEvents,
  fetchMessages,
  fetchSecurityCounts,
  fetchSecurityEvents,
  fetchSessionStats,
  fetchSessions,
} from "./api";
import { Sidebar } from "./components/Sidebar";
import { Toolbar } from "./components/Toolbar";
import { MessageTable } from "./components/MessageTable";
import { DetailPanel } from "./components/DetailPanel";
import { StatsBar } from "./components/StatsBar";
import { Pagination } from "./components/Pagination";
import { SecurityView } from "./components/SecurityView";
import { ContextView } from "./components/ContextView";
import { InjectView } from "./components/InjectView";

const PAGE_SIZE = 100;
const AUTO_REFRESH_MS = 2000;

type View = "messages" | "security" | "context" | "inject";

export function App() {
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [sessionsError, setSessionsError] = useState<string | null>(null);
  const [selectedSessionId, setSelectedSessionId] = useState<number | null>(null);

  const [view, setView] = useState<View>("messages");

  const [direction, setDirection] = useState<Direction | "">("");
  const [method, setMethod] = useState("");
  const [query, setQuery] = useState("");
  const [offset, setOffset] = useState(0);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const [messagesResp, setMessagesResp] = useState<MessagesResponse | null>(null);
  const [messagesError, setMessagesError] = useState<string | null>(null);
  const [selectedMessageId, setSelectedMessageId] = useState<number | null>(null);

  const [stats, setStats] = useState<SessionStats | null>(null);

  const [securityOffset, setSecurityOffset] = useState(0);
  const [securityResp, setSecurityResp] = useState<SecurityEventsResponse | null>(null);
  const [securityError, setSecurityError] = useState<string | null>(null);
  const [securityCounts, setSecurityCounts] = useState<SecurityCounts | null>(null);

  const [contextReport, setContextReport] = useState<ContextReport | null>(null);
  const [contextError, setContextError] = useState<string | null>(null);

  const [injectOffset, setInjectOffset] = useState(0);
  const [injectResp, setInjectResp] = useState<InjectEventsResponse | null>(null);
  const [injectError, setInjectError] = useState<string | null>(null);
  const [injectCounts, setInjectCounts] = useState<InjectCounts | null>(null);

  // Monotonic request counters so a slow, stale response (e.g. from a
  // session we've since navigated away from) can't clobber a newer one.
  const messagesSeqRef = useRef(0);
  const statsSeqRef = useRef(0);
  const securitySeqRef = useRef(0);
  const securityCountsSeqRef = useRef(0);
  const contextSeqRef = useRef(0);
  const injectSeqRef = useRef(0);
  const injectCountsSeqRef = useRef(0);

  // Reset paging/selection when switching sessions or changing filters.
  useEffect(() => {
    setOffset(0);
    setSelectedMessageId(null);
    setSecurityOffset(0);
    setInjectOffset(0);
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

  const loadSecurity = useCallback(() => {
    if (selectedSessionId === null) {
      securitySeqRef.current += 1;
      setSecurityResp(null);
      return;
    }
    const seq = ++securitySeqRef.current;
    fetchSecurityEvents(selectedSessionId, { limit: PAGE_SIZE, offset: securityOffset })
      .then((r) => {
        if (securitySeqRef.current !== seq) return; // superseded by a newer request
        setSecurityResp(r);
        setSecurityError(null);
      })
      .catch((e: unknown) => {
        if (securitySeqRef.current !== seq) return;
        setSecurityError(e instanceof Error ? e.message : String(e));
      });
  }, [selectedSessionId, securityOffset]);

  const loadSecurityCounts = useCallback(() => {
    if (selectedSessionId === null) {
      securityCountsSeqRef.current += 1;
      setSecurityCounts(null);
      return;
    }
    const seq = ++securityCountsSeqRef.current;
    fetchSecurityCounts(selectedSessionId)
      .then((r) => {
        if (securityCountsSeqRef.current !== seq) return; // superseded by a newer request
        setSecurityCounts(r);
      })
      .catch(() => {
        if (securityCountsSeqRef.current !== seq) return;
        setSecurityCounts(null);
      });
  }, [selectedSessionId]);

  const loadContext = useCallback(() => {
    if (selectedSessionId === null) {
      contextSeqRef.current += 1;
      setContextReport(null);
      return;
    }
    const seq = ++contextSeqRef.current;
    fetchContext(selectedSessionId)
      .then((r) => {
        if (contextSeqRef.current !== seq) return; // superseded by a newer request
        setContextReport(r);
        setContextError(null);
      })
      .catch((e: unknown) => {
        if (contextSeqRef.current !== seq) return;
        setContextError(e instanceof Error ? e.message : String(e));
      });
  }, [selectedSessionId]);

  const loadInject = useCallback(() => {
    if (selectedSessionId === null) {
      injectSeqRef.current += 1;
      setInjectResp(null);
      return;
    }
    const seq = ++injectSeqRef.current;
    fetchInjectEvents(selectedSessionId, { limit: PAGE_SIZE, offset: injectOffset })
      .then((r) => {
        if (injectSeqRef.current !== seq) return; // superseded by a newer request
        setInjectResp(r);
        setInjectError(null);
      })
      .catch((e: unknown) => {
        if (injectSeqRef.current !== seq) return;
        setInjectError(e instanceof Error ? e.message : String(e));
      });
  }, [selectedSessionId, injectOffset]);

  const loadInjectCounts = useCallback(() => {
    if (selectedSessionId === null) {
      injectCountsSeqRef.current += 1;
      setInjectCounts(null);
      return;
    }
    const seq = ++injectCountsSeqRef.current;
    fetchInjectCounts(selectedSessionId)
      .then((r) => {
        if (injectCountsSeqRef.current !== seq) return; // superseded by a newer request
        setInjectCounts(r);
      })
      .catch(() => {
        if (injectCountsSeqRef.current !== seq) return;
        setInjectCounts(null);
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

  useEffect(() => {
    loadSecurity();
  }, [loadSecurity]);

  useEffect(() => {
    loadSecurityCounts();
  }, [loadSecurityCounts]);

  useEffect(() => {
    loadContext();
  }, [loadContext]);

  useEffect(() => {
    loadInject();
  }, [loadInject]);

  useEffect(() => {
    loadInjectCounts();
  }, [loadInjectCounts]);

  const autoRefreshRef = useRef({
    loadSessions,
    loadMessages,
    loadStats,
    loadSecurity,
    loadSecurityCounts,
    loadContext,
    loadInject,
    loadInjectCounts,
  });
  autoRefreshRef.current = {
    loadSessions,
    loadMessages,
    loadStats,
    loadSecurity,
    loadSecurityCounts,
    loadContext,
    loadInject,
    loadInjectCounts,
  };
  const viewRef = useRef(view);
  viewRef.current = view;

  useEffect(() => {
    if (!autoRefresh) return;
    const id = setInterval(() => {
      autoRefreshRef.current.loadSessions();
      autoRefreshRef.current.loadMessages();
      autoRefreshRef.current.loadStats();
      // Security events/counts, the context report and inject events are only
      // polled while their own view is visible.
      if (viewRef.current === "security") {
        autoRefreshRef.current.loadSecurity();
        autoRefreshRef.current.loadSecurityCounts();
      }
      if (viewRef.current === "context") {
        autoRefreshRef.current.loadContext();
      }
      if (viewRef.current === "inject") {
        autoRefreshRef.current.loadInject();
        autoRefreshRef.current.loadInjectCounts();
      }
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
            <div className="view-tabs">
              <button
                className={"view-tab" + (view === "messages" ? " view-tab-active" : "")}
                onClick={() => setView("messages")}
              >
                Messages
              </button>
              <button
                className={"view-tab" + (view === "security" ? " view-tab-active" : "")}
                onClick={() => setView("security")}
              >
                Security
                {securityCounts && securityCounts.blocked > 0 && (
                  <span className="view-tab-alert" title="blocked events present" />
                )}
              </button>
              <button
                className={"view-tab" + (view === "context" ? " view-tab-active" : "")}
                onClick={() => setView("context")}
              >
                Context
              </button>
              <button
                className={"view-tab" + (view === "inject" ? " view-tab-active" : "")}
                onClick={() => setView("inject")}
              >
                Inject
                {injectCounts &&
                  injectCounts.delay + injectCounts.error + injectCounts.drop + injectCounts.truncate > 0 && (
                    <span className="view-tab-alert" title="fault-injection events present" />
                  )}
              </button>
            </div>
            {view === "messages" ? (
              <>
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
            ) : view === "security" ? (
              <>
                {securityError && (
                  <div className="banner banner-error">Failed to load security events: {securityError}</div>
                )}
                <SecurityView
                  counts={securityCounts}
                  events={securityResp?.events ?? []}
                  total={securityResp?.total ?? 0}
                  offset={securityOffset}
                  limit={PAGE_SIZE}
                  onOffsetChange={setSecurityOffset}
                />
              </>
            ) : view === "context" ? (
              <>
                {contextError && (
                  <div className="banner banner-error">Failed to load context report: {contextError}</div>
                )}
                <ContextView report={contextReport} />
              </>
            ) : (
              <>
                {injectError && (
                  <div className="banner banner-error">Failed to load inject events: {injectError}</div>
                )}
                <InjectView
                  counts={injectCounts}
                  events={injectResp?.events ?? []}
                  total={injectResp?.total ?? 0}
                  offset={injectOffset}
                  limit={PAGE_SIZE}
                  onOffsetChange={setInjectOffset}
                />
              </>
            )}
          </>
        )}
      </main>
    </div>
  );
}
