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
} from "./api";
import {
  deleteSession,
  fetchContext,
  fetchInjectCounts,
  fetchInjectEvents,
  fetchMessages,
  fetchSecurityCounts,
  fetchSecurityEvents,
  fetchSessionStats,
  fetchSessions,
} from "./api";
import { useApi } from "./hooks/useApi";
import { useHashRoute } from "./hooks/useHashRoute";
import { useTheme } from "./hooks/useTheme";
import { Sidebar } from "./components/Sidebar";
import { Toolbar } from "./components/Toolbar";
import { MessageTable } from "./components/MessageTable";
import { DetailPanel } from "./components/DetailPanel";
import { StatsBar } from "./components/StatsBar";
import { Pagination } from "./components/Pagination";
import { SecurityView } from "./components/SecurityView";
import { ContextView } from "./components/ContextView";
import { InjectView } from "./components/InjectView";
import { ConfirmDialog } from "./components/ConfirmDialog";
import { useToast } from "./components/Toast";

const PAGE_SIZE = 100;
const AUTO_REFRESH_MS = 3000;

export function App() {
  const { route, setRoute } = useHashRoute();
  const { theme, toggleTheme } = useTheme();
  const toast = useToast();

  // The hash is the single source of truth for session / view / message. A malformed
  // or stale id parses to null, which the "pick a default session" effect below heals.
  const parsedSession = route.sessionId !== null ? Number(route.sessionId) : null;
  const selectedSessionId =
    parsedSession !== null && Number.isFinite(parsedSession) ? parsedSession : null;
  const view = route.view;
  const parsedMessage = route.messageId !== null ? Number(route.messageId) : null;
  const selectedMessageId =
    parsedMessage !== null && Number.isFinite(parsedMessage) ? parsedMessage : null;

  // Filters and paging stay local (deliberately out of the hash).
  const [direction, setDirection] = useState<Direction | "">("");
  const [method, setMethod] = useState("");
  const [query, setQuery] = useState("");
  const [offset, setOffset] = useState(0);
  const [securityOffset, setSecurityOffset] = useState(0);
  const [injectOffset, setInjectOffset] = useState(0);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Off-canvas sidebar drawer (only shown at the <=900px breakpoint).
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Pending delete confirmation (null = dialog closed). Carries the label so the
  // modal can name the session being deleted.
  const [confirmDelete, setConfirmDelete] = useState<{ id: number; label: string } | null>(null);

  // Lets the `/` shortcut focus the raw-JSON search box in the toolbar.
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Polling tick: advances every AUTO_REFRESH_MS while auto-refresh is on. Resources
  // fold it into their deps to re-fetch; per-view resources gate it on their view so
  // e.g. security is only polled while the Security tab is open (initial loads, driven
  // by the session dep, still happen regardless of the visible view).
  //
  // The interval pauses while the tab is hidden (no point polling a background tab)
  // and fires one immediate catch-up tick when the tab becomes visible again.
  const [pollTick, setPollTick] = useState(0);
  useEffect(() => {
    if (!autoRefresh) return;
    let id: number | undefined;
    const stop = () => {
      if (id !== undefined) {
        window.clearInterval(id);
        id = undefined;
      }
    };
    const start = () => {
      stop();
      id = window.setInterval(() => setPollTick((t) => t + 1), AUTO_REFRESH_MS);
    };
    const onVisibility = () => {
      if (document.hidden) {
        stop();
      } else {
        setPollTick((t) => t + 1); // immediate refresh on return to foreground
        start();
      }
    };
    document.addEventListener("visibilitychange", onVisibility);
    if (!document.hidden) start();
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      stop();
    };
  }, [autoRefresh]);

  const sid = selectedSessionId;

  const {
    data: sessionsData,
    error: sessionsError,
    retry: retrySessions,
  } = useApi(fetchSessions, [pollTick]);
  const sessions = sessionsData?.sessions ?? [];

  const messagesApi = useApi<MessagesResponse>(
    sid === null
      ? null
      : (signal) =>
          fetchMessages(
            sid,
            { limit: PAGE_SIZE, offset, direction, method: method.trim(), q: query.trim() },
            signal,
          ),
    [sid, offset, direction, method, query, pollTick],
  );

  const statsApi = useApi<SessionStats>(
    sid === null ? null : (signal) => fetchSessionStats(sid, signal),
    [sid, pollTick],
  );

  const securityApi = useApi<SecurityEventsResponse>(
    sid === null
      ? null
      : (signal) => fetchSecurityEvents(sid, { limit: PAGE_SIZE, offset: securityOffset }, signal),
    [sid, securityOffset, view === "security" ? pollTick : 0],
  );

  const securityCountsApi = useApi<SecurityCounts>(
    sid === null ? null : (signal) => fetchSecurityCounts(sid, signal),
    [sid, view === "security" ? pollTick : 0],
  );

  const contextApi = useApi<ContextReport>(
    sid === null ? null : (signal) => fetchContext(sid, signal),
    [sid, view === "context" ? pollTick : 0],
  );

  const injectApi = useApi<InjectEventsResponse>(
    sid === null
      ? null
      : (signal) => fetchInjectEvents(sid, { limit: PAGE_SIZE, offset: injectOffset }, signal),
    [sid, injectOffset, view === "inject" ? pollTick : 0],
  );

  const injectCountsApi = useApi<InjectCounts>(
    sid === null ? null : (signal) => fetchInjectCounts(sid, signal),
    [sid, view === "inject" ? pollTick : 0],
  );

  // Once sessions are known, make sure the hash points at a real one. Runs on the
  // initial deep link (keeping a valid target), and after a delete (the deleted id no
  // longer matches → fall back to the newest remaining session).
  useEffect(() => {
    if (sessions.length === 0) return;
    const exists =
      route.sessionId !== null && sessions.some((s) => String(s.id) === route.sessionId);
    if (!exists) {
      setRoute({ sessionId: String(sessions[0].id), messageId: null });
    }
  }, [sessions, route.sessionId, setRoute]);

  // Reset paging when the session or filters change.
  useEffect(() => {
    setOffset(0);
    setSecurityOffset(0);
    setInjectOffset(0);
  }, [sid, direction, method, query]);

  const clearSelectedMessage = useCallback(() => {
    if (route.messageId !== null) setRoute({ messageId: null });
  }, [route.messageId, setRoute]);

  // Filter changes drop the current message selection (it may no longer be in view),
  // mirroring the old behaviour. Session changes handle this per navigation path:
  // a sidebar click clears the message explicitly; a deep link keeps it.
  const handleDirectionChange = useCallback(
    (v: Direction | "") => {
      setDirection(v);
      clearSelectedMessage();
    },
    [clearSelectedMessage],
  );
  const handleMethodChange = useCallback(
    (v: string) => {
      setMethod(v);
      clearSelectedMessage();
    },
    [clearSelectedMessage],
  );
  const handleQueryChange = useCallback(
    (v: string) => {
      setQuery(v);
      clearSelectedMessage();
    },
    [clearSelectedMessage],
  );

  const handleSelectSession = useCallback(
    (id: number) => {
      setRoute({ sessionId: String(id), messageId: null });
      setDrawerOpen(false); // close the drawer after a pick on small screens
    },
    [setRoute],
  );
  const handleSelectMessage = useCallback(
    (id: number) => setRoute({ messageId: String(id) }),
    [setRoute],
  );
  const handleSelectView = useCallback(
    (v: typeof view) => setRoute({ view: v }),
    [setRoute],
  );

  const handleDeleteSession = useCallback(
    (id: number) => {
      const label = sessions.find((s) => s.id === id)?.label ?? `#${id}`;
      setConfirmDelete({ id, label });
    },
    [sessions],
  );

  const confirmDeleteSession = useCallback(() => {
    if (confirmDelete === null) return;
    const { id, label } = confirmDelete;
    setConfirmDelete(null);
    deleteSession(id)
      .then(() => {
        toast(`Deleted session ${label}`, "success");
        // Reload the list; if the deleted session was the selected one, the
        // "pick a default session" effect re-selects the newest remaining.
        retrySessions();
      })
      .catch((e: unknown) =>
        toast(`Failed to delete session: ${e instanceof Error ? e.message : String(e)}`, "error"),
      );
  }, [confirmDelete, retrySessions, toast]);

  // Global keyboard shortcuts. Skipped while typing in a field (except Esc, which
  // blurs it) and while a modal is open (the dialog handles its own keys).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (document.querySelector(".modal-scrim")) return;
      const target = e.target as HTMLElement | null;
      const tag = target?.tagName;
      const typing =
        tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || !!target?.isContentEditable;
      if (typing) {
        if (e.key === "Escape") target?.blur();
        return;
      }

      if (e.key === "Escape") {
        // Peel back one layer: selected frame → drawer.
        if (selectedMessageId !== null) clearSelectedMessage();
        else if (drawerOpen) setDrawerOpen(false);
        return;
      }

      // The remaining shortcuts only make sense on the Messages view.
      if (view !== "messages") return;

      if (e.key === "/") {
        e.preventDefault();
        searchInputRef.current?.focus();
        return;
      }

      if (e.key === "j" || e.key === "k") {
        const msgs = messagesApi.data?.messages ?? [];
        if (msgs.length === 0) return;
        e.preventDefault();
        const idx = msgs.findIndex((m) => m.id === selectedMessageId);
        const next =
          e.key === "j"
            ? idx < 0
              ? 0
              : Math.min(msgs.length - 1, idx + 1)
            : idx < 0
              ? msgs.length - 1
              : Math.max(0, idx - 1);
        handleSelectMessage(msgs[next].id);
        return;
      }

      if (e.key === "Enter") {
        // Redundant with j/k (which select directly): pick the first row when
        // nothing is selected yet.
        const msgs = messagesApi.data?.messages ?? [];
        if (selectedMessageId === null && msgs.length > 0) {
          e.preventDefault();
          handleSelectMessage(msgs[0].id);
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [
    view,
    selectedMessageId,
    drawerOpen,
    clearSelectedMessage,
    handleSelectMessage,
    messagesApi.data,
  ]);

  const stats = statsApi.data;
  const securityCounts = securityCountsApi.data;
  const injectCounts = injectCountsApi.data;

  const hasNoSessions = sessions.length === 0 && !sessionsError;

  return (
    <div className="app">
      <header className="app-header">
        <button
          type="button"
          className="drawer-toggle"
          onClick={() => setDrawerOpen((o) => !o)}
          aria-label="Toggle sessions sidebar"
          aria-expanded={drawerOpen}
        >
          ☰
        </button>
        <div className="wordmark">
          <span className="wordmark-led" aria-hidden="true" />
          MCPGLASS
        </div>
        <div className="header-right">
          <button
            type="button"
            className="theme-toggle"
            onClick={toggleTheme}
            title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            aria-label="Toggle colour theme"
          >
            {theme === "dark" ? "☀" : "☾"}
          </button>
        </div>
      </header>
      <div className="app-body">
        <Sidebar
          sessions={sessions}
          selectedId={selectedSessionId}
          onSelect={handleSelectSession}
          onDelete={handleDeleteSession}
          open={drawerOpen}
        />
        {drawerOpen && (
          <div className="drawer-scrim" onClick={() => setDrawerOpen(false)} aria-hidden="true" />
        )}
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
                onClick={() => handleSelectView("messages")}
              >
                Messages
              </button>
              <button
                className={"view-tab" + (view === "security" ? " view-tab-active" : "")}
                onClick={() => handleSelectView("security")}
              >
                Security
                {securityCounts && securityCounts.blocked > 0 && (
                  <span className="tab-alert tab-alert-red" title="blocked events present">
                    {securityCounts.blocked}
                  </span>
                )}
              </button>
              <button
                className={"view-tab" + (view === "context" ? " view-tab-active" : "")}
                onClick={() => handleSelectView("context")}
              >
                Context
              </button>
              <button
                className={"view-tab" + (view === "inject" ? " view-tab-active" : "")}
                onClick={() => handleSelectView("inject")}
              >
                Inject
                {injectCounts &&
                  injectCounts.delay + injectCounts.error + injectCounts.drop + injectCounts.truncate > 0 && (
                    <span className="tab-alert" title="fault-injection events present">
                      {injectCounts.delay + injectCounts.error + injectCounts.drop + injectCounts.truncate}
                    </span>
                  )}
              </button>
            </div>
            {view === "messages" ? (
              <>
                <Toolbar
                  direction={direction}
                  onDirectionChange={handleDirectionChange}
                  method={method}
                  onMethodChange={handleMethodChange}
                  query={query}
                  onQueryChange={handleQueryChange}
                  autoRefresh={autoRefresh}
                  onAutoRefreshChange={setAutoRefresh}
                  searchInputRef={searchInputRef}
                />
                {messagesApi.error && (
                  <div className="banner banner-error">Failed to load messages: {messagesApi.error}</div>
                )}
                <div className="content-split">
                  <div className="table-pane">
                    <MessageTable
                      messages={messagesApi.data?.messages ?? []}
                      selectedId={selectedMessageId}
                      onSelect={handleSelectMessage}
                      loading={messagesApi.loading}
                    />
                    <Pagination
                      offset={offset}
                      limit={PAGE_SIZE}
                      total={messagesApi.data?.total ?? 0}
                      onOffsetChange={setOffset}
                    />
                  </div>
                  <DetailPanel messageId={selectedMessageId} />
                </div>
              </>
            ) : view === "security" ? (
              <>
                {securityApi.error && (
                  <div className="banner banner-error">Failed to load security events: {securityApi.error}</div>
                )}
                <SecurityView
                  counts={securityCounts}
                  events={securityApi.data?.events ?? []}
                  total={securityApi.data?.total ?? 0}
                  offset={securityOffset}
                  limit={PAGE_SIZE}
                  onOffsetChange={setSecurityOffset}
                  loading={securityApi.loading}
                />
              </>
            ) : view === "context" ? (
              <>
                {contextApi.error && (
                  <div className="banner banner-error">Failed to load context report: {contextApi.error}</div>
                )}
                <ContextView report={contextApi.data} />
              </>
            ) : (
              <>
                {injectApi.error && (
                  <div className="banner banner-error">Failed to load inject events: {injectApi.error}</div>
                )}
                <InjectView
                  counts={injectCounts}
                  events={injectApi.data?.events ?? []}
                  total={injectApi.data?.total ?? 0}
                  offset={injectOffset}
                  limit={PAGE_SIZE}
                  onOffsetChange={setInjectOffset}
                  loading={injectApi.loading}
                />
              </>
            )}
          </>
        )}
        </main>
      </div>
      <ConfirmDialog
        open={confirmDelete !== null}
        title="Delete session"
        message={
          <>
            Delete session <span className="mono">{confirmDelete?.label}</span> and all its recorded
            messages? This cannot be undone. (Tool fingerprints are kept.)
          </>
        }
        confirmLabel="Delete"
        variant="danger"
        onConfirm={confirmDeleteSession}
        onCancel={() => setConfirmDelete(null)}
      />
    </div>
  );
}
