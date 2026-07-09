<!-- DRAFT — do not publish as-is -->

# Reddit r/mcp draft

Repo: https://github.com/q86865511/mcpglass

## Candidate titles / openers (pick one)

1. `I built a local "Wireshark + firewall" for MCP traffic — see exactly what your client and servers say to each other`
2. `mcpglass: a transparent local proxy that records (and can filter) all your MCP traffic`
3. `Tired of guessing what your MCP server actually received? I made a proxy that shows you`

## Body (one version)

**The one-line pitch:** if you've ever stared at a misbehaving MCP tool call and thought
"what did my client actually *send*, and what did the server actually *reply*?" — mcpglass
sits between them and shows you, in a local dashboard, without changing how anything
behaves.

The MCP Inspector is great for poking a server by hand, but it can't see the real
conversation your client is already having. mcpglass is a transparent proxy for that real
traffic. It's a single Rust binary.

What it does:

- **One-command setup** — `mcpglass attach claude-code` (also claude-desktop, cursor)
  rewrites your client config to route existing servers through the proxy, with backups.
  `detach` restores everything; `--dry-run` previews. Or wrap a single server explicitly
  with `mcpglass wrap -- <server cmd>`.
- **Both transports** — stdio servers get wrapped; Streamable HTTP servers go through a
  local gateway (JSON + SSE stream through untouched, recorded on the side).
- **A real dashboard** — timeline of every request/response/notification, per-session
  view, payload inspector, per-method latency.
- **Security layer** — per-tool allow/deny, secret-leak detection (masked in the audit view),
  and tool-fingerprint pinning that flags rug-pulls (a server silently changing a tool
  description after you approved it). Defaults to monitor mode (flag, never block);
  enforce is opt-in.
- **Context bloat analysis** — a heuristic estimate of how many tokens each server's
  `tools/list` schemas eat, and which tools are the fattest.
- **Replay + fault injection** — re-send a recorded request, or inject delay/error/drop/
  truncate to test how your client handles a flaky server.

Two things I want to be upfront about, since this is a proxy in your critical path:

- **Fail-open is the rule.** Any internal error in the proxy never blocks or delays your
  traffic — the worst case is that a debugging tool breaks your working setup, and it's
  built specifically to avoid that. Recording is a side-channel tap, not an inline filter.
- **Local-only, and honest about it.** Everything lives in local SQLite and never leaves
  your machine. That database records full raw traffic, including secrets that flow
  through it — it's a traffic recorder by design. The secret filter masks values in the
  audit view, but treat the DB like a packet capture.

It's open source, Apache-2.0, open-core. Still early but the whole pipeline above works
today.

Repo: https://github.com/q86865511/mcpglass

If you build or run MCP servers, I'd love for you to try it and tell me where it helps or
gets in the way. Bug reports and issues very welcome — especially edge cases in config
takeover across different clients, and anything around the HTTP gateway.
