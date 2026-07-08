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

export interface HealthResponse {
  version: string;
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(path);
  if (!res.ok) {
    throw new Error(`${path} -> HTTP ${res.status}`);
  }
  return (await res.json()) as T;
}

export function fetchSessions(): Promise<SessionsResponse> {
  return getJson<SessionsResponse>("/api/sessions");
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
): Promise<MessagesResponse> {
  const params = new URLSearchParams();
  params.set("limit", String(filters.limit));
  params.set("offset", String(filters.offset));
  if (filters.direction) params.set("direction", filters.direction);
  if (filters.method) params.set("method", filters.method);
  if (filters.q) params.set("q", filters.q);
  return getJson<MessagesResponse>(
    `/api/sessions/${sessionId}/messages?${params.toString()}`,
  );
}

export function fetchMessageDetail(id: number): Promise<MessageDetail> {
  return getJson<MessageDetail>(`/api/messages/${id}`);
}

export function fetchSessionStats(sessionId: number): Promise<SessionStats> {
  return getJson<SessionStats>(`/api/sessions/${sessionId}/stats`);
}

export function fetchHealth(): Promise<HealthResponse> {
  return getJson<HealthResponse>("/api/health");
}

export interface SecurityEventsFilters {
  limit: number;
  offset: number;
}

export function fetchSecurityEvents(
  sessionId: number,
  filters: SecurityEventsFilters,
): Promise<SecurityEventsResponse> {
  const params = new URLSearchParams();
  params.set("limit", String(filters.limit));
  params.set("offset", String(filters.offset));
  return getJson<SecurityEventsResponse>(
    `/api/sessions/${sessionId}/security?${params.toString()}`,
  );
}

export function fetchSecurityCounts(sessionId: number): Promise<SecurityCounts> {
  return getJson<SecurityCounts>(`/api/sessions/${sessionId}/security/counts`);
}
