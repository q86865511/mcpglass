<!-- DRAFT — do not publish as-is -->

# Show HN draft

Repo: https://github.com/q86865511/mcpglass

## Candidate titles (pick one, <= 80 chars)

1. `Show HN: mcpglass – a Wireshark and firewall for MCP traffic`
2. `Show HN: mcpglass – see and filter what your AI client sends to MCP servers`
3. `Show HN: mcpglass – a local transparent proxy for debugging MCP servers`

## Body (one version)

I've been building MCP servers for a few months, and the thing that kept slowing me
down was a dumb one: I couldn't actually see what my client was sending and what the
server was replying. The official MCP Inspector is a side-channel test harness — you
point it at a server and poke it by hand. It never sees the *real* conversation between,
say, Claude Code and the server it's already talking to. When a tool call misbehaves in
the real client, you're stuck guessing.

mcpglass is a transparent proxy that sits in the middle of that real conversation. It's
a single Rust binary. You run `mcpglass attach claude-code` and it rewrites your client
config (with backups — `detach` restores everything) so existing servers route through
the proxy. stdio servers get wrapped; Streamable HTTP servers get pointed at a local
gateway. Then every request, response, and notification shows up in a local dashboard:
per-session timeline, payload inspector, per-method latency.

Three design decisions I want to be upfront about, because they're the interesting part:

**Fail-open is a hard rule.** The proxy is on the critical path between your client and
your servers, and the worst possible outcome is that my debugging tool breaks your
working setup. So any internal error — a parse failure, a DB write error, a panic in the
policy code — never blocks or delays traffic. Unknown JSON-RPC fields pass straight
through. The only things that can intentionally interrupt a message are the ones you
explicitly asked for (an enforce-mode policy match, or a configured fault-injection
rule), and even those return an in-protocol JSON-RPC error rather than severing the
connection. If the HTTP upstream is down, it honestly returns 502 — it never synthesizes
a fake JSON-RPC response to cover for the server.

**Observation is a side-channel tap, not an inline filter.** For server→client traffic,
the bytes are forwarded first and recorded after, on a separate thread. Recording can
never add latency or backpressure to the wire. The only synchronous, blocking decision
point is client→server requests, and that's only because a security policy sometimes has
to decide *before* a call reaches the server (e.g. deny a tool, or flag a leaking
secret). That asymmetry is deliberate.

**Everything stays in local SQLite, and I'll be blunt about the tradeoff:** the database
records full raw traffic, including any secret that flows through it. It's a traffic
recorder — that's the point — and the data never leaves your machine. The secret-leak
filter masks values in the security audit view, but the honest framing is "this is a
local packet capture of your MCP traffic," not "this is a redaction tool."

On top of the plumbing there's a security layer (per-tool allow/deny, secret detection,
and tool-fingerprint pinning that flags rug-pulls where a server silently changes a tool
description across runs), context-bloat analysis (a heuristic estimate of how many tokens
each server's tool schemas eat, and which tools are fattest), request replay, and fault
injection (delay/error/drop/truncate) for testing client resilience. Security defaults to
monitor mode — observe and flag, never block — and enforce is strictly opt-in.

It's open-core, Apache-2.0. It's early (stdio + HTTP interception, dashboard, security
layer, analytics, replay, injection all work today). I'd genuinely like feedback on the
fail-open model and the local-storage tradeoff — if you run MCP servers, I'd love to hear
where this does or doesn't fit your workflow, and what's missing.

## Expected questions and how to answer them

**"How is this different from just reading my client's logs?"**
Client logs, when they exist, are unstructured and client-specific, and most clients don't
log the full JSON-RPC payloads at all. mcpglass gives you a structured, per-session,
searchable record of every message in both directions with latency, plus analysis on top
(fingerprint diffs, token accounting, replay). It's the difference between `printf`
debugging and a packet capture.

**"Why should I trust your proxy in the middle of my traffic?"**
You shouldn't have to trust it much, and that's the point of fail-open: the proxy is
designed so its own failures can't break your traffic. It's a single Rust binary, source
is Apache-2.0, and it runs entirely on localhost — nothing phones home. `attach` backs up
your config before touching it and `detach --dry-run` shows exactly what it would restore.
If you don't want config takeover at all, `mcpglass wrap -- <server cmd>` just wraps one
server explicitly.

**"How complete is the HTTP transport support?"**
The gateway handles Streamable HTTP (spec 2025-06-18): both plain JSON and SSE responses
stream through untouched while a side-channel tap records them. It's loopback-only with
Origin/Host validation to prevent DNS-rebinding. One current limitation I'll call out:
fault injection does not apply to HTTP SSE response streams in this version (stdio and
non-streaming HTTP are covered).

**"Does enforce mode risk breaking my client?"**
Enforce is opt-in. When it blocks, it returns a well-formed in-protocol JSON-RPC error to
the client rather than dropping the connection, so a compliant client handles it like any
other tool error. Monitor mode (the default) never blocks anything.

**"Windows/macOS/Linux?"**
Single Rust binary; the dashboard frontend is built and embedded at compile time. (State
current platform coverage here before posting.)
