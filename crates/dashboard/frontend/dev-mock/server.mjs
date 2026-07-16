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

    // A sprinkle of metadata-only recordings (as `--record metadata` produces):
    // the body is dropped (raw = "") and its original byte length kept in raw_len,
    // so the detail panel's "metadata-only" rendering has something to show.
    const rawLen = Buffer.byteLength(raw, "utf8");
    const metadataOnly = isValidJson && i % 19 === 5;

    messages.push({
      id,
      session_id: sessionId,
      ts_ms: ts,
      direction,
      method: isNotification && direction === "s2c" ? null : method,
      rpc_id: rpcId,
      is_valid_json: isValidJson,
      is_error: isError,
      size: rawLen,
      raw: metadataOnly ? "" : raw,
      raw_len: metadataOnly ? rawLen : null,
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

// Read and JSON-parse a request body (for POST routes). Returns null on invalid
// JSON so the caller can answer 400.
function collectBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      if (!text) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(text));
      } catch {
        resolve(null);
      }
    });
  });
}

// Simulated on-disk DB size, shrunk by a real (non-dry-run) prune so the toast's
// "before → after" readout shows movement.
let mockDbSize = 4_800_000;

function prunePayload(body) {
  const hasAge = typeof body.older_than_ms === "number";
  const hasSize = typeof body.max_size_bytes === "number";
  const dryRun = body.dry_run === true;
  // Fixed plausible estimate — enough to populate the preview readout.
  const stats = { sessions: 1, messages: 42, security_events: 0, inject_events: 2 };
  const before = mockDbSize;
  let after = before;
  if (!dryRun) {
    // Realise the freed space (a real prune vacuums for max-size / when asked).
    after = Math.max(1_200_000, before - 1_200_000);
    mockDbSize = after;
  }
  return { hasAge, hasSize, payload: { stats, db_size_before: before, db_size_after: after } };
}

function exportBundle(sessionId) {
  const def = sessionDefs.find((d) => d.id === sessionId);
  if (!def) return null;
  const messages = (messagesBySession.get(sessionId) ?? []).slice(0, 3).map((m) => ({
    id: m.id,
    ts_ms: m.ts_ms,
    direction: m.direction,
    method: m.method,
    rpc_id: m.rpc_id,
    // Pretend a secret was masked, to mirror the real (always-masked) export.
    raw: m.raw.replace(/AKIA[0-9A-Z]{16}/g, "AKIA****************"),
  }));
  return {
    note: "masked session export (dev mock) — secrets redacted",
    session: {
      id: def.id,
      label: def.label,
      command: def.command,
      started_at_ms: def.started_at_ms,
      ended_at_ms: def.ended_at_ms,
    },
    messages,
  };
}

// A ContextReport-shaped fixture (see api.ts). Populated for a session that has
// messages; unknown sessions report zero tools (exercises the empty state).
function contextReport(sessionId) {
  if (!messagesBySession.has(sessionId)) {
    return {
      approximate: true,
      tool_count: 0,
      total_chars: 0,
      est_total_tokens: 0,
      tools: [],
      fat_tools: [],
    };
  }
  const rawTools = [
    { name: "fs_read", total_chars: 3200, description_tokens: 620 },
    { name: "http_fetch", total_chars: 2100, description_tokens: 410 },
    { name: "search", total_chars: 1400, description_tokens: 280 },
    { name: "fs_write", total_chars: 900, description_tokens: 150 },
    { name: "prompts_get", total_chars: 400, description_tokens: 70 },
  ];
  const total_chars = rawTools.reduce((a, t) => a + t.total_chars, 0);
  const est_total_tokens = Math.round(total_chars / 4);
  const tools = rawTools.map((t) => {
    const est_tokens = Math.round(t.total_chars / 4);
    return {
      name: t.name,
      total_chars: t.total_chars,
      est_tokens,
      description_tokens: t.description_tokens,
      pct: est_total_tokens === 0 ? 0 : Math.round((est_tokens / est_total_tokens) * 1000) / 10,
    };
  });
  // Tools whose description alone is "fat" (mirrors the backend's fat_tools).
  const fat_tools = rawTools.filter((t) => t.description_tokens > 400).map((t) => t.name);
  return { approximate: true, tool_count: tools.length, total_chars, est_total_tokens, tools, fat_tools };
}

const server = createServer(async (req, res) => {
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

  // DELETE /api/sessions/{id}: drop the session and all its messages/events, keeping
  // (conceptually) its tool fingerprints. Mirrors the real backend's 404 on unknown id.
  if (parts.length === 3 && parts[1] === "sessions" && req.method === "DELETE") {
    const id = Number(parts[2]);
    const idx = sessionDefs.findIndex((d) => d.id === id);
    if (idx === -1) {
      send(404, { error: "session not found" });
      return;
    }
    const msgs = messagesBySession.get(id) ?? [];
    const security = securityEventsBySession.get(id) ?? [];
    const inject = injectEventsBySession.get(id) ?? [];
    for (const m of msgs) messagesById.delete(m.id);
    messagesBySession.delete(id);
    securityEventsBySession.delete(id);
    injectEventsBySession.delete(id);
    sessionDefs.splice(idx, 1);
    send(200, {
      sessions: 1,
      messages: msgs.length,
      security_events: security.length,
      inject_events: inject.length,
    });
    return;
  }

  if (parts.length === 2 && parts[1] === "health" && req.method === "GET") {
    // Flip `replay` to false here to exercise the dashboard's replay-gating
    // (the Replay button then renders disabled). Kept true so the mock mirrors a
    // full-capability backend.
    send(200, { version: "0.1.0", capabilities: { replay: true } });
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

  // GET /api/sessions/{id}/context: context-bloat report fixture.
  if (parts.length === 4 && parts[1] === "sessions" && parts[3] === "context" && req.method === "GET") {
    const sessionId = Number(parts[2]);
    if (!messagesBySession.has(sessionId)) {
      send(404, { error: "session not found" });
      return;
    }
    send(200, contextReport(sessionId));
    return;
  }

  // GET /api/sessions/{id}/export: masked bundle, offered as a file download.
  if (parts.length === 4 && parts[1] === "sessions" && parts[3] === "export" && req.method === "GET") {
    const sessionId = Number(parts[2]);
    const bundle = exportBundle(sessionId);
    if (!bundle) {
      send(404, { error: "session not found" });
      return;
    }
    res.setHeader("Content-Disposition", `attachment; filename="mcpglass-session-${sessionId}.json"`);
    send(200, bundle);
    return;
  }

  // POST /api/prune: delete by age and/or size. At least one condition required
  // (else 400, mirroring the backend). dry_run returns an estimate without change.
  if (parts.length === 2 && parts[1] === "prune" && req.method === "POST") {
    const body = await collectBody(req);
    if (body === null) {
      res.setHeader("Content-Type", "text/plain");
      res.writeHead(400);
      res.end("invalid JSON body");
      return;
    }
    const { hasAge, hasSize, payload } = prunePayload(body);
    if (!hasAge && !hasSize) {
      res.setHeader("Content-Type", "text/plain");
      res.writeHead(400);
      res.end("prune needs at least one of older_than_ms or max_size_bytes");
      return;
    }
    send(200, payload);
    return;
  }

  // POST /api/messages/{id}/replay: re-send a recorded c2s request (dev stub).
  // Only a client->server request with a method + id is replayable (else 400),
  // mirroring the real backend's categorised errors.
  if (
    parts.length === 4 &&
    parts[1] === "messages" &&
    parts[3] === "replay" &&
    req.method === "POST"
  ) {
    const id = Number(parts[2]);
    const full = messagesById.get(id);
    if (!full) {
      send(404, { error: "message not found" });
      return;
    }
    if (full.direction !== "c2s" || full.method === null || full.rpc_id === null) {
      res.setHeader("Content-Type", "text/plain");
      res.writeHead(400);
      res.end("message is not a replayable client->server request");
      return;
    }
    send(200, {
      transport: "stdio",
      response_raw: JSON.stringify({ jsonrpc: "2.0", id: full.rpc_id, result: { ok: true, replayed: true } }),
      note: "fresh handshake, possible side effects, not recorded (dev mock)",
    });
    return;
  }

  send(404, { error: "not found" });
});

server.listen(PORT, HOST, () => {
  console.log(`mcpglass mock API listening on http://${HOST}:${PORT}`);
});
