# mcpglass

[![CI](https://github.com/q86865511/mcpglass/actions/workflows/ci.yml/badge.svg)](https://github.com/q86865511/mcpglass/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

**Wireshark + firewall for MCP traffic.** A transparent proxy — a single Rust binary — that sits
between any AI client (Claude Code, Claude Desktop, Cursor, ...) and your MCP servers, giving you
debugging, observability, auditing, and security. All data stays on your machine.

> Status: early development (v0.1.0 — stdio + HTTP interception, config takeover, dashboard, security layer, context analytics, replay, fault injection).

![The mcpglass dashboard](docs/assets/dashboard-overview.png)

## Install

There is no prebuilt binary yet — install from source. You need a [Rust
toolchain](https://rustup.rs/) (1.80+) and [pnpm](https://pnpm.io/) (for the dashboard frontend,
which is embedded into the binary at build time):

```sh
git clone https://github.com/q86865511/mcpglass
cd mcpglass

# 1. Build the dashboard frontend first — cargo embeds its output.
#    Skip this and you get a placeholder dashboard page.
cd crates/dashboard/frontend && pnpm install && pnpm build && cd ../../..

# 2a. Build the binary into ./target/release/mcpglass
cargo build --release --workspace

# 2b. ...or install it onto your PATH
cargo install --path crates/cli
```

## Quickstart

Point your client's existing stdio MCP servers through the proxy, use the client normally, then
inspect the traffic:

```sh
# 1. Rewrite the client config so its servers run through mcpglass (a backup is
#    written first; `mcpglass detach` restores it). Use --dry-run to preview.
mcpglass attach claude-code

# 2. Use Claude Code as usual — every request/response is now recorded locally.

# 3. Open the dashboard timeline at http://127.0.0.1:7411
mcpglass dashboard
```

For url-type (Streamable HTTP) MCP servers, also run the long-lived gateway that `attach` repoints
them at: `mcpglass gateway` (see [docs/cli.md](docs/cli.md)).

## Documentation

- [docs/cli.md](docs/cli.md) — every subcommand, its flags, and examples.
- [docs/configuration.md](docs/configuration.md) — policy and fault-injection TOML reference.
- [docs/security-model.md](docs/security-model.md) — the fail-open design, monitor/enforce, and threat model.

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
  - **Secret-leak filtering** — scans outgoing `tools/call` arguments for API keys/tokens (AWS, GitHub, OpenAI, Anthropic, ...) and flags them (values are masked in the audit view; the raw traffic log still stores payloads verbatim).
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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the build/test/lint workflow and PR conventions, and
[SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

Apache-2.0
