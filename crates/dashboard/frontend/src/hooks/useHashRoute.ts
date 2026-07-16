import { useCallback, useEffect, useState } from "react";

// The four top-level views, and the default when the hash omits one.
export const VIEWS = ["messages", "security", "context", "inject"] as const;
export type View = (typeof VIEWS)[number];
export const DEFAULT_VIEW: View = "messages";

/**
 * The app's navigable state, serialised into the URL hash as
 * `#/s/{sessionId}/{view}?msg={messageId}`. It is the single source of truth for
 * which session, view and message are open, so reloading or pasting a URL restores
 * the same place. Filters/paging deliberately stay out of the hash.
 */
export interface Route {
  sessionId: string | null;
  view: View;
  messageId: string | null;
}

function isView(v: string): v is View {
  return (VIEWS as readonly string[]).includes(v);
}

export function parseHash(hash: string): Route {
  let path = hash.startsWith("#") ? hash.slice(1) : hash;

  let query = "";
  const q = path.indexOf("?");
  if (q >= 0) {
    query = path.slice(q + 1);
    path = path.slice(0, q);
  }

  const segments = path.split("/").filter((s) => s.length > 0);

  let sessionId: string | null = null;
  let view: View = DEFAULT_VIEW;
  // Expect ["s", sessionId, view?]. Anything else is treated as "no selection".
  if (segments[0] === "s" && segments.length >= 2) {
    sessionId = decodeURIComponent(segments[1]);
    if (segments.length >= 3 && isView(segments[2])) {
      view = segments[2];
    }
  }

  let messageId: string | null = null;
  if (query) {
    const msg = new URLSearchParams(query).get("msg");
    if (msg) messageId = msg;
  }
  // A message only makes sense inside a session.
  if (sessionId === null) messageId = null;

  return { sessionId, view, messageId };
}

export function serializeRoute(route: Route): string {
  if (route.sessionId === null) return "#/";
  let out = `#/s/${encodeURIComponent(route.sessionId)}/${route.view}`;
  if (route.messageId !== null) {
    const params = new URLSearchParams();
    params.set("msg", route.messageId);
    out += `?${params.toString()}`;
  }
  return out;
}

export interface HashRoute {
  route: Route;
  // Merge a partial change into the current route and write it to the URL hash.
  // Dropping the session also drops any message selection.
  setRoute: (patch: Partial<Route>) => void;
}

export function useHashRoute(): HashRoute {
  const [route, setRouteState] = useState<Route>(() => parseHash(window.location.hash));

  useEffect(() => {
    const onHashChange = () => setRouteState(parseHash(window.location.hash));
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const setRoute = useCallback((patch: Partial<Route>) => {
    // Read the live hash as the source of truth so this callback needs no deps and
    // never acts on a stale closure.
    const next: Route = { ...parseHash(window.location.hash), ...patch };
    if (next.sessionId === null) next.messageId = null;
    const nextHash = serializeRoute(next);
    if (nextHash !== window.location.hash) {
      // Triggers "hashchange", which syncs state above.
      window.location.hash = nextHash;
    } else {
      // Hash already correct (e.g. a no-op patch); make sure state matches.
      setRouteState(next);
    }
  }, []);

  return { route, setRoute };
}
