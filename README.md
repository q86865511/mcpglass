# mcpglass

**Wireshark + firewall for MCP traffic.** A transparent proxy — a single Rust binary — that sits
between any AI client (Claude Code, Claude Desktop, Cursor, ...) and your MCP servers, giving you
debugging, observability, auditing, and security. All data stays on your machine.

> Status: early development (Phase 3 complete — stdio + HTTP interception, config takeover, dashboard, security layer, context analytics, replay, fault injection).

## Why

- The official MCP Inspector is a side-channel test harness — it can't see the *real* traffic
  between your client and your servers.
- MCP servers can silently change their tool descriptions after you approve them (rug-pull).
- You have no idea how much of your context window each server's tool schemas are eating.

## Features

- **Transparent interception** — `mcpglass wrap -- <server command>` runs any stdio MCP server with zero behavior change (fail-open: proxy errors never block traffic).
- **HTTP (streamable) transport** — `mcpglass gateway` runs a local reverse proxy for Streamable HTTP MCP servers (spec 2025-06-18): JSON and SSE responses stream through untouched while a side-channel tap records them; policy decisions apply per request; loopback-only with Origin/Host validation against DNS rebinding.
- **One-command takeover** — `mcpglass attach [claude-code|claude-desktop|cursor|all]` rewrites client configs to route existing servers through the proxy (with backups) — stdio servers are wrapped, url servers are pointed at the gateway with their upstream recorded in `gateway.toml`; `mcpglass detach` restores them. `--dry-run` previews.
- **Local dashboard** — `mcpglass dashboard` opens a timeline of every request/response/notification: per-session view, filters, payload inspector, per-method latency, and a Security tab.
- **Security layer** — `mcpglass wrap --policy <file>` enforces a TOML policy:
  - **Tool integrity pinning** — fingerprints each server's tool definitions and flags a change across runs (rug-pull detection).
  - **Secret-leak filtering** — scans outgoing `tools/call` arguments for API keys/tokens (AWS, GitHub, OpenAI, Anthropic, ...) and flags them (masked in storage).
  - **Per-tool allow/deny** — allow-lists or deny-lists tools by name.
  - **Append-only audit log** — every decision is recorded, visible in the dashboard's Security tab.

  Default mode is **monitor** (observe and flag, never block). Opt into **enforce** (`--enforce`
  or `mode = "enforce"`) to actively refuse denied/leaking calls: the proxy returns an in-protocol
  JSON-RPC error to the client instead of forwarding — it never severs the connection, and any
  proxy-internal error always fails open.
- **Context bloat analysis** — `mcpglass bloat` (or the dashboard's Context tab) estimates how many tokens each server's tool schemas cost, ranks the fattest tools, and flags over-long descriptions. Token counts are a heuristic approximation (~4 chars/token), not an exact tokenizer.
- **Request replay** — `mcpglass replay <message-id>` (or the Replay button in the dashboard's message detail) re-sends a recorded client→server request: it re-spawns the stdio server (or re-initializes the HTTP upstream for a fresh session) and shows the response. Replay is an out-of-band probe — nothing it does is recorded. It can trigger real side effects, so the dashboard button asks for confirmation first.
- **Fault injection** — `mcpglass wrap --inject <file>` / `mcpglass gateway --inject <file>` applies a TOML ruleset that simulates faults on live traffic (delay, synthetic JSON-RPC error, dropped frame, truncation), in either direction, to test server resilience and client fault-tolerance. It is off by default; when enabled it is a deliberate, in-protocol intervention (like enforce), and the injection machinery itself still fails open. HTTP SSE response streams are not injected in this version.

> **Privacy note:** the local SQLite database records **full raw traffic**, including any secret
> that flows through it. This is by design (it is a traffic recorder) and the data never leaves
> your machine; secret filtering masks values only in the security audit view.

## Build

The dashboard frontend must be built before the Rust workspace embeds it
(without it you get a placeholder page):

```sh
cd crates/dashboard/frontend && pnpm install && pnpm build && cd ../../..
cargo build --workspace
cargo test --workspace
```

## License

Apache-2.0
