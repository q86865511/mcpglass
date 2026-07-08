# mcpglass

**Wireshark + firewall for MCP traffic.** A transparent proxy — a single Rust binary — that sits
between any AI client (Claude Code, Claude Desktop, Cursor, ...) and your MCP servers, giving you
debugging, observability, auditing, and security. All data stays on your machine.

> Status: early development (Phase 1 MVP — interception, config takeover, local dashboard).

## Why

- The official MCP Inspector is a side-channel test harness — it can't see the *real* traffic
  between your client and your servers.
- MCP servers can silently change their tool descriptions after you approve them (rug-pull).
- You have no idea how much of your context window each server's tool schemas are eating.

## Features

- **Transparent interception** — `mcpglass wrap -- <server command>` runs any stdio MCP server with zero behavior change (fail-open: proxy errors never block traffic).
- **One-command takeover** — `mcpglass attach [claude-code|claude-desktop|cursor|all]` rewrites client configs to route existing servers through the proxy (with backups); `mcpglass detach` restores them. `--dry-run` previews.
- **Local dashboard** — `mcpglass dashboard` opens a timeline of every request/response/notification: per-session view, filters, payload inspector, per-method latency.

Planned (Phase 2+): tool integrity pinning (rug-pull detection), secret-leak filtering, per-tool allow/deny policies, audit log, HTTP transport, context bloat analytics.

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
