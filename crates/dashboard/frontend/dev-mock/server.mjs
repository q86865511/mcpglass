// Zero-dependency mock server for local frontend development.
// Serves fixed fixture data that matches the mcpglass dashboard API contract
// (see crates/dashboard/frontend — the real Rust backend implements the same
// shape). Run with `pnpm mock` (or `node dev-mock/server.mjs`).

import { createServer } from "node:http";

const HOST = "127.0.0.1";
const PORT = 7411;

const NOW = Date.parse("2026-07-08T12:00:00Z");

const METHODS = [
  "initialize",
  "tools/list",
  "tools/call",
  "resources/list",
  "resources/read",
  "prompts/list",
];

function buildSessionMessages(sessionId, count, startTs) {
  const messages = [];
  let rpcCounter = 1;
  for (let i = 0; i < count; i++) {
    const id = sessionId * 100000 + i + 1;
    const ts = startTs + i * 750;
    const method = METHODS[i % METHODS.length];
    const isNotification = i % 17 === 0; // notifications have no rpc_id
    const direction = i % 2 === 0 ? "c2s" : "s2c";
    const isError = direction === "s2c" && i % 23 === 0;
    const isValidJson = !(i % 41 === 0); // sprinkle a few malformed entries
    const rpcId = isNotification ? null : String(rpcCounter++);

    let raw;
    if (!isValidJson) {
      raw = "{not valid json,,,";
    } else if (direction === "c2s") {
      raw = JSON.stringify({
        jsonrpc: "2.0",
        id: rpcId,
        method,
        params: { index: i, note: `request #${i} for session ${sessionId}` },
      });
    } else if (isError) {
      raw = JSON.stringify({
        jsonrpc: "2.0",
        id: rpcId,
        error: { code: -32000, message: `synthetic error for ${method}` },
      });
    } else {
      raw = JSON.stringify({
        jsonrpc: "2.0",
        id: rpcId,
        result: { ok: true, echoedMethod: method, index: i },
      });
    }

    messages.push({
      id,
      session_id: sessionId,
      ts_ms: ts,
      direction,
      method: isNotification && direction === "s2c" ? null : method,
      rpc_id: rpcId,
      is_valid_json: isValidJson,
      is_error: isError,
      size: Buffer.byteLength(raw, "utf8"),
      raw,
    });
  }
  return messages;
}

const sessionDefs = [
  {
    id: 2,
    label: "server-filesystem",
    command: "npx -y @modelcontextprotocol/server-filesystem .",
    started_at_ms: NOW - 5 * 60_000,
    ended_at_ms: null, // live
    count: 128,
    protocol_version: "2025-11-25",
    client_protocol_version: "2025-06-18",
    protocol_version_source: "initialize",
  },
  {
    id: 1,
    label: "server-fetch",
    command: "npx -y @modelcontextprotocol/server-fetch",
    started_at_ms: NOW - 60 * 60_000,
    ended_at_ms: NOW - 55 * 60_000,
    count: 42,
    // A legacy / unobserved session: no protocol version recorded.
    protocol_version: null,
    client_protocol_version: null,
    protocol_version_source: null,
  },
];

const messagesBySession = new Map();
const messagesById = new Map();
for (const def of sessionDefs) {
  const msgs = buildSessionMessages(def.id, def.count, def.started_at_ms);
  messagesBySession.set(def.id, msgs);
  for (const m of msgs) messagesById.set(m.id, m);
}

// Security events fixture: session 2 (the "live" one) gets a mix of all three
// kinds plus both flagged/blocked outcomes, so the badge row and table have
// something interesting to render in dev. Session 1 stays clean (empty state).
function buildSecurityEvents(sessionId, startTs) {
  const rows = [
    {
      kind: "policy_deny",
      rule: "deny-write-tools",
      detail: "tool 'fs_write' denied by policy (write tools disabled)",
      tool_name: "fs_write",
      rpc_id: "17",
      action_taken: "blocked",
    },
    {
      kind: "secret_leak",
      rule: "aws-access-key",
      detail: "AKIA****************** redacted in tool result",
      tool_name: "http_fetch",
      rpc_id: null,
      action_taken: "flagged",
    },
    {
      kind: "secret_leak",
      rule: "generic-api-key",
      detail: "sk-live-**************** redacted in tool result",
      tool_name: "http_fetch",
      rpc_id: "23",
      action_taken: "blocked",
    },
    {
      kind: "fingerprint_change",
      rule: "tool-fingerprint",
      detail: "fingerprint for 'search' changed since first sighting (rug-pull suspicion)",
      tool_name: "search",
      rpc_id: null,
      action_taken: "flagged",
    },
    {
      kind: "policy_deny",
      rule: "deny-network-tools",
      detail: "tool 'http_fetch' denied by policy (outbound host not allow-listed)",
      tool_name: "http_fetch",
      rpc_id: "31",
      action_taken: "flagged",
    },
    {
      kind: "fingerprint_change",
      rule: "tool-fingerprint",
      detail: "fingerprint for 'tools/list' changed since first sighting",
      tool_name: null,
      rpc_id: null,
      action_taken: "blocked",
    },
  ];
  return rows.map((r, i) => ({
    id: sessionId * 1000 + i + 1,
    session_id: sessionId,
    ts_ms: startTs + i * 1500,
    ...r,
  }));
}

const securityEventsBySession = new Map();
securityEventsBySession.set(2, buildSecurityEvents(2, sessionDefs[0].started_at_ms));
securityEventsBySession.set(1, []); // clean session -> exercises the empty state

function securityEventsPayload(sessionId, query) {
  const all = securityEventsBySession.get(sessionId) ?? [];
  const limit = Math.max(1, Number(query.get("limit")) || 100);
  const offset = Math.max(0, Number(query.get("offset")) || 0);
  const total = all.length;
  const page = all.slice(offset, offset + limit).map(({ session_id, ...rest }) => rest);
  return { total, events: page };
}

function securityCountsPayload(sessionId) {
  const all = securityEventsBySession.get(sessionId) ?? [];
  let policy_deny = 0;
  let secret_leak = 0;
  let fingerprint_change = 0;
  let blocked = 0;
  for (const e of all) {
    if (e.kind === "policy_deny") policy_deny++;
    if (e.kind === "secret_leak") secret_leak++;
    if (e.kind === "fingerprint_change") fingerprint_change++;
    if (e.action_taken === "blocked") blocked++;
  }
  return { policy_deny, secret_leak, fingerprint_change, blocked };
}

// Inject-events fixture: session 2 (the "live" one) gets one of each fault
// kind so the badge row and table have something interesting to render in
// dev. Session 1 stays clean (empty state).
function buildInjectEvents(sessionId, startTs) {
  const rows = [
    {
      direction: "c2s",
      rule: "slow-tools-call",
      fault: "delay",
      detail: "delayed 'tools/call' by 500ms",
      method: "tools/call",
      rpc_id: "12",
    },
    {
      direction: "s2c",
      rule: "flaky-http-fetch",
      fault: "error",
      detail: "synthetic error injected for 'http_fetch' response",
      method: "tools/call",
      rpc_id: "18",
    },
    {
      direction: "s2c",
      rule: "drop-notifications",
      fault: "drop",
      detail: "dropped a 'notifications/progress' message",
      method: "notifications/progress",
      rpc_id: null,
    },
    {
      direction: "s2c",
      rule: "truncate-large-results",
      fault: "truncate",
      detail: "truncated 'resources/read' response to 2048 bytes",
      method: "resources/read",
      rpc_id: "29",
    },
  ];
  return rows.map((r, i) => ({
    id: sessionId * 1000 + i + 1,
    session_id: sessionId,
    ts_ms: startTs + i * 1500,
    ...r,
  }));
}

const injectEventsBySession = new Map();
injectEventsBySession.set(2, buildInjectEvents(2, sessionDefs[0].started_at_ms));
injectEventsBySession.set(1, []); // clean session -> exercises the empty state

function injectEventsPayload(sessionId, query) {
  const all = injectEventsBySession.get(sessionId) ?? [];
  const limit = Math.max(1, Number(query.get("limit")) || 100);
  const offset = Math.max(0, Number(query.get("offset")) || 0);
  const total = all.length;
  const page = all.slice(offset, offset + limit).map(({ session_id, ...rest }) => rest);
  return { total, events: page };
}

function injectCountsPayload(sessionId) {
  const all = injectEventsBySession.get(sessionId) ?? [];
  let delay = 0;
  let error = 0;
  let drop = 0;
  let truncate = 0;
  for (const e of all) {
    if (e.fault === "delay") delay++;
    if (e.fault === "error") error++;
    if (e.fault === "drop") drop++;
    if (e.fault === "truncate") truncate++;
  }
  return { delay, error, drop, truncate };
}

function toSummary(full) {
  const { raw, session_id, ...rest } = full;
  const preview = raw.length > 120 ? raw.slice(0, 120) : raw;
  return { ...rest, preview };
}

function sessionsPayload() {
  const sessions = sessionDefs
    .slice()
    .sort((a, b) => b.started_at_ms - a.started_at_ms)
    .map((def) => ({
      id: def.id,
      label: def.label,
      command: def.command,
      started_at_ms: def.started_at_ms,
      ended_at_ms: def.ended_at_ms,
      message_count: messagesBySession.get(def.id).length,
      protocol_version: def.protocol_version,
      client_protocol_version: def.client_protocol_version,
      protocol_version_source: def.protocol_version_source,
    }));
  return { sessions };
}

function messagesPayload(sessionId, query) {
  const all = messagesBySession.get(sessionId) ?? [];
  const limit = Math.max(1, Number(query.get("limit")) || 100);
  const offset = Math.max(0, Number(query.get("offset")) || 0);
  const direction = query.get("direction") || "";
  const method = query.get("method") || "";
  const q = query.get("q") || "";

  let filtered = all;
  if (direction) filtered = filtered.filter((m) => m.direction === direction);
  if (method) filtered = filtered.filter((m) => m.method === method);
  if (q) filtered = filtered.filter((m) => m.raw.includes(q));

  const total = filtered.length;
  const page = filtered.slice(offset, offset + limit);
  return { total, messages: page.map(toSummary) };
}

function statsPayload(sessionId) {
  const all = messagesBySession.get(sessionId) ?? [];
  const byMethod = new Map();
  let invalid = 0;
  let errors = 0;

  for (const m of all) {
    if (!m.is_valid_json) invalid++;
    if (m.is_error) errors++;
    if (!m.method) continue;
    const key = m.method;
    if (!byMethod.has(key)) byMethod.set(key, []);
    // Synthetic latency: derive a stable pseudo-random value from id.
    const latency = 20 + ((m.id * 37) % 900);
    byMethod.get(key).push(latency);
  }

  const per_method = Array.from(byMethod.entries()).map(([method, latencies]) => {
    // Mirror the real backend: "prompts/list" stands in for a method whose
    // occurrences are all notifications/unpaired responses, so there is no
    // measurable round-trip latency — the API reports null, not 0.
    if (method === "prompts/list") {
      return { method, count: latencies.length, avg_latency_ms: null, max_latency_ms: null };
    }
    const sum = latencies.reduce((a, b) => a + b, 0);
    return {
      method,
      count: latencies.length,
      avg_latency_ms: Math.round((sum / latencies.length) * 10) / 10,
      max_latency_ms: Math.max(...latencies),
    };
  });

  return {
    per_method,
    totals: { messages: all.length, invalid, errors },
  };
}

const server = createServer((req, res) => {
  const url = new URL(req.url ?? "/", `http://${HOST}:${PORT}`);
  const parts = url.pathname.split("/").filter(Boolean); // e.g. ["api","sessions","2","messages"]

  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*");

  const send = (status, body) => {
    res.writeHead(status);
    res.end(JSON.stringify(body));
  };

  if (parts[0] !== "api") {
    send(404, { error: "not found" });
    return;
  }

  if (parts.length === 2 && parts[1] === "sessions" && req.method === "GET") {
    send(200, sessionsPayload());
    return;
  }

  if (parts.length === 2 && parts[1] === "health" && req.method === "GET") {
    send(200, { version: "0.1.0" });
    return;
  }

  if (parts.length === 4 && parts[1] === "sessions" && parts[3] === "messages" && req.method === "GET") {
    const sessionId = Number(parts[2]);
    if (!messagesBySession.has(sessionId)) {
      send(404, { error: "session not found" });
      return;
    }
    send(200, messagesPayload(sessionId, url.searchParams));
    return;
  }

  if (parts.length === 4 && parts[1] === "sessions" && parts[3] === "stats" && req.method === "GET") {
    const sessionId = Number(parts[2]);
    if (!messagesBySession.has(sessionId)) {
      send(404, { error: "session not found" });
      return;
    }
    send(200, statsPayload(sessionId));
    return;
  }

  if (parts.length === 4 && parts[1] === "sessions" && parts[3] === "security" && req.method === "GET") {
    const sessionId = Number(parts[2]);
    if (!messagesBySession.has(sessionId)) {
      send(404, { error: "session not found" });
      return;
    }
    send(200, securityEventsPayload(sessionId, url.searchParams));
    return;
  }

  if (
    parts.length === 5 &&
    parts[1] === "sessions" &&
    parts[3] === "security" &&
    parts[4] === "counts" &&
    req.method === "GET"
  ) {
    const sessionId = Number(parts[2]);
    if (!messagesBySession.has(sessionId)) {
      send(404, { error: "session not found" });
      return;
    }
    send(200, securityCountsPayload(sessionId));
    return;
  }

  if (parts.length === 4 && parts[1] === "sessions" && parts[3] === "inject" && req.method === "GET") {
    // Unlike the security routes, the real backend answers an unknown session
    // with 200 + empty here, so the mock mirrors that.
    send(200, injectEventsPayload(Number(parts[2]), url.searchParams));
    return;
  }

  if (
    parts.length === 5 &&
    parts[1] === "sessions" &&
    parts[3] === "inject" &&
    parts[4] === "counts" &&
    req.method === "GET"
  ) {
    send(200, injectCountsPayload(Number(parts[2])));
    return;
  }

  if (parts.length === 3 && parts[1] === "messages" && req.method === "GET") {
    const id = Number(parts[2]);
    const full = messagesById.get(id);
    if (!full) {
      send(404, { error: "message not found" });
      return;
    }
    const preview = full.raw.length > 120 ? full.raw.slice(0, 120) : full.raw;
    send(200, { ...full, preview });
    return;
  }

  send(404, { error: "not found" });
});

server.listen(PORT, HOST, () => {
  console.log(`mcpglass mock API listening on http://${HOST}:${PORT}`);
});
