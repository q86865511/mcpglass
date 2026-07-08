# mcp-lens

**Wireshark + firewall for MCP traffic.** A transparent proxy — a single Rust binary — that sits
between any AI client (Claude Code, Claude Desktop, Cursor, ...) and your MCP servers, giving you
debugging, observability, auditing, and security. All data stays on your machine.

> Status: early development (Phase 0 — transparent stdio interception spike).

## Why

- The official MCP Inspector is a side-channel test harness — it can't see the *real* traffic
  between your client and your servers.
- MCP servers can silently change their tool descriptions after you approve them (rug-pull).
- You have no idea how much of your context window each server's tool schemas are eating.

## Planned features

- **Transparent interception** — wrap any stdio MCP server with zero behavior change (fail-open).
- **Local dashboard** — timeline of every tool call / resource / prompt, latency, payloads.
- **One-command takeover** — rewrite client configs to route existing servers through the proxy, reversibly.
- **Security layer** — tool integrity pinning, secret-leak filtering, per-tool allow/deny, audit log.
- **Context bloat analytics** — token cost per server, trimming suggestions.

## Build

```sh
cargo build --workspace
cargo test --workspace
```

## License

Apache-2.0
