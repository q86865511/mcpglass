// Typed wrappers around the mcpglass dashboard HTTP API. All endpoints are
// relative (/api/...) — in dev, vite.config.ts proxies them to the mock
// server or the real Rust backend; in production the same-origin Rust
// server serves both the API and this bundle.

export interface SessionSummary {
  id: number;
  label: string;
  command: string;
  started_at_ms: number;
  ended_at_ms: number | null;
  message_count: number;
  // MCP protocol version the server selected (null when unobserved, e.g. stdio
  // traffic with no captured handshake or a legacy pre-v6 session).
  protocol_version: string | null;
  // MCP protocol version the client proposed (null when unobserved).
  client_protocol_version: string | null;
  // How the version was observed: "initialize" | "header" | null.
  protocol_version_source: string | null;
}

export interface SessionsResponse {
  sessions: SessionSummary[];
}

export type Direction = "c2s" | "s2c";

export interface MessageSummary {
  id: number;
  ts_ms: number;
  direction: Direction;
  method: string | null;
  rpc_id: string | null;
  is_valid_json: boolean;
  is_error: boolean;
  size: number;
  preview: string;
}

export interface MessagesResponse {
  total: number;
  messages: MessageSummary[];
}

export interface MessageDetail extends MessageSummary {
  raw: string;
  session_id: number;
  // Original byte length when the frame was recorded metadata-only (raw is then
  // ""); null for a full recording. Lets the UI distinguish "empty body" from
  // "body deliberately not recorded".
  raw_len: number | null;
}

export interface MethodStat {
  method: string;
  count: number;
  // null when the backend has no measurable round-trip latency for this
  // method (e.g. it only ever appears as a notification or an unpaired
  // response).
  avg_latency_ms: number | null;
  max_latency_ms: number | null;
}

export interface SessionStats {
  per_method: MethodStat[];
  totals: {
    messages: number;
    invalid: number;
    errors: number;
  };
}

export type SecurityEventKind = "policy_deny" | "secret_leak" | "fingerprint_change";
export type ActionTaken = "flagged" | "blocked";

export interface SecurityEvent {
  id: number;
  ts_ms: number;
  kind: SecurityEventKind;
  rule: string;
  // Already masked by the backend (e.g. a leaked key comes back as
  // "AKIA****...**") — safe to render as-is.
  detail: string;
  tool_name: string | null;
  rpc_id: string | null;
  action_taken: ActionTaken;
}

export interface SecurityEventsResponse {
  total: number;
  events: SecurityEvent[];
}

export interface SecurityCounts {
  policy_deny: number;
  secret_leak: number;
  fingerprint_change: number;
  blocked: number;
}

export type InjectFault = "delay" | "error" | "drop" | "truncate";

export interface InjectEvent {
  id: number;
  ts_ms: number;
  direction: Direction;
  rule: string;
  fault: InjectFault;
  // Human-readable detail of the fault applied (e.g. delay duration, injected
  // error payload).
  detail: string;
  method: string | null;
  rpc_id: string | null;
}

export interface InjectEventsResponse {
  total: number;
  events: InjectEvent[];
}

export interface InjectCounts {
  delay: number;
  error: number;
  drop: number;
  truncate: number;
}

// Which optional backend features this dashboard build wired in, so the UI can
// hide/disable controls it can't drive (currently just replay).
export interface Capabilities {
  replay: boolean;
}

export interface HealthResponse {
  version: string;
  capabilities: Capabilities;
}

// Row counts a prune removed (or, in a dry run, would remove). Mirrors the
// backend's PruneStatsDto; tool_fingerprints is intentionally never here (it is
// the cross-session rug-pull baseline and is always kept).
export interface PruneStats {
  sessions: number;
  messages: number;
  security_events: number;
  inject_events: number;
}

// A POST /api/prune request. At least one of older_than_ms / max_size_bytes is
// required (the backend answers 400 otherwise). older_than_ms is a *duration*
// (cutoff = now - value), not an absolute timestamp.
export interface PruneRequest {
  older_than_ms?: number;
  max_size_bytes?: number;
  dry_run: boolean;
  vacuum: boolean;
}

export interface PruneResponse {
  stats: PruneStats;
  db_size_before: number;
  db_size_after: number;
}

// Same-origin URL for a session's masked export bundle. Used as an <a download>
// href so the browser saves the file directly (no fetch — a fetch would buffer
// the whole bundle in memory just to re-offer it as a download).
export function sessionExportUrl(id: number): string {
  return `/api/sessions/${id}/export`;
}

// Delete recorded sessions by age and/or to a size target (tool fingerprints are
// always kept, guaranteed by the backend). On a non-2xx the backend returns a
// plain-text reason, surfaced as the Error.
export async function postPrune(body: PruneRequest): Promise<PruneResponse> {
  const res = await fetch("/api/prune", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || `prune -> HTTP ${res.status}`);
  }
  return (await res.json()) as PruneResponse;
}

async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(path, signal ? { signal } : undefined);
  if (!res.ok) {
    throw new Error(`${path} -> HTTP ${res.status}`);
  }
  return (await res.json()) as T;
}

export function fetchSessions(signal?: AbortSignal): Promise<SessionsResponse> {
  return getJson<SessionsResponse>("/api/sessions", signal);
}

// Delete a session and all its recorded messages / security / inject events (its
// tool fingerprints are kept). On a non-2xx the backend returns a plain-text
// reason, surfaced as the Error.
export async function deleteSession(id: number): Promise<void> {
  const res = await fetch(`/api/sessions/${id}`, { method: "DELETE" });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || `delete session -> HTTP ${res.status}`);
  }
}

export interface MessageFilters {
  limit: number;
  offset: number;
  direction?: Direction | "";
  method?: string;
  q?: string;
}

export function fetchMessages(
  sessionId: number,
  filters: MessageFilters,
  signal?: AbortSignal,
): Promise<MessagesResponse> {
  const params = new URLSearchParams();
  params.set("limit", String(filters.limit));
  params.set("offset", String(filters.offset));
  if (filters.direction) params.set("direction", filters.direction);
  if (filters.method) params.set("method", filters.method);
  if (filters.q) params.set("q", filters.q);
  return getJson<MessagesResponse>(
    `/api/sessions/${sessionId}/messages?${params.toString()}`,
    signal,
  );
}

export function fetchMessageDetail(id: number, signal?: AbortSignal): Promise<MessageDetail> {
  return getJson<MessageDetail>(`/api/messages/${id}`, signal);
}

export interface ReplayResult {
  // Which path ran: "stdio" (server re-spawned) or "http" (fresh HTTP handshake).
  transport: string;
  // The server's answer to the replayed request, or null if none was isolated.
  response_raw: string | null;
  // Caveats: fresh handshake, possible side effects, not recorded.
  note: string;
}

// Re-send a recorded c2s request to its server (out of band, never recorded).
// On a non-2xx the backend returns a plain-text reason, surfaced as the Error.
export async function postReplay(id: number): Promise<ReplayResult> {
  const res = await fetch(`/api/messages/${id}/replay`, { method: "POST" });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || `replay -> HTTP ${res.status}`);
  }
  return (await res.json()) as ReplayResult;
}

export function fetchSessionStats(
  sessionId: number,
  signal?: AbortSignal,
): Promise<SessionStats> {
  return getJson<SessionStats>(`/api/sessions/${sessionId}/stats`, signal);
}

export function fetchHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return getJson<HealthResponse>("/api/health", signal);
}

export interface SecurityEventsFilters {
  limit: number;
  offset: number;
}

export function fetchSecurityEvents(
  sessionId: number,
  filters: SecurityEventsFilters,
  signal?: AbortSignal,
): Promise<SecurityEventsResponse> {
  const params = new URLSearchParams();
  params.set("limit", String(filters.limit));
  params.set("offset", String(filters.offset));
  return getJson<SecurityEventsResponse>(
    `/api/sessions/${sessionId}/security?${params.toString()}`,
    signal,
  );
}

export function fetchSecurityCounts(
  sessionId: number,
  signal?: AbortSignal,
): Promise<SecurityCounts> {
  return getJson<SecurityCounts>(`/api/sessions/${sessionId}/security/counts`, signal);
}

// Context-bloat analysis: how many context tokens a session's advertised
// tool catalog costs, estimated via a zero-dependency chars/4 heuristic —
// `approximate` is always true, this is never a real tokenizer count.
export interface ToolBloat {
  name: string;
  total_chars: number;
  est_tokens: number;
  description_tokens: number;
  // Share of est_total_tokens, 0-100 (0 when the total is 0).
  pct: number;
}

export interface ContextReport {
  approximate: boolean;
  tool_count: number;
  total_chars: number;
  est_total_tokens: number;
  // Sorted heaviest-first.
  tools: ToolBloat[];
  // Names of tools whose description alone estimates over the fat threshold.
  fat_tools: string[];
}

export function fetchContext(
  sessionId: number,
  signal?: AbortSignal,
): Promise<ContextReport> {
  return getJson<ContextReport>(`/api/sessions/${sessionId}/context`, signal);
}

export interface InjectEventsFilters {
  limit: number;
  offset: number;
}

export function fetchInjectEvents(
  sessionId: number,
  filters: InjectEventsFilters,
  signal?: AbortSignal,
): Promise<InjectEventsResponse> {
  const params = new URLSearchParams();
  params.set("limit", String(filters.limit));
  params.set("offset", String(filters.offset));
  return getJson<InjectEventsResponse>(
    `/api/sessions/${sessionId}/inject?${params.toString()}`,
    signal,
  );
}

export function fetchInjectCounts(
  sessionId: number,
  signal?: AbortSignal,
): Promise<InjectCounts> {
  return getJson<InjectCounts>(`/api/sessions/${sessionId}/inject/counts`, signal);
}
