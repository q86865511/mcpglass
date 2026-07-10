# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Differential conformance CI** — a new `Conformance` workflow runs the official
  MCP conformance suite (`@modelcontextprotocol/conformance`) twice against the same
  reference server (`server-everything`): once connected directly and once through an
  mcpglass gateway. `scripts/conformance-diff.mjs` asserts the proxied run fails no
  scenario the direct run passes, so a transparency regression in the gateway turns
  the build red, while the reference server's own conformance gaps (which fail both
  runs) are ignored. The job also asserts the gateway recorded a negotiated
  `protocol_version` for the session, and soft-skips if the third-party reference
  server can't be fetched or started.
- **MCP 2025-11-25 support** — the proxy tracks the current MCP spec. The parser and
  tap treat every 2025-11-25 wire addition (tasks, icons, `sampling` tool calls,
  URL-mode elicitation, SSE resumption) as pure pass-through, forwarding and recording
  each frame byte-for-byte.
- **Passive protocol-version observation** — each session now records the protocol
  version it negotiated: read from the `initialize` handshake (client-proposed and
  server-selected), or, on the HTTP gateway, from the `MCP-Protocol-Version` header
  when no handshake is captured. The version is stored per session, shown in the
  dashboard's session list, and used to faithfully reconstruct the handshake on
  `replay` (a legacy session with no recorded version falls back to the build
  default). Observation is a side-channel read only — it never touches the wire.
- **Tool fingerprint v3** — tool integrity pinning now folds in `outputSchema`, so a
  server that quietly rewrites the *result contract* a tool promises (a genuine
  rug-pull surface) is flagged. Existing fingerprints upgrade silently on next
  sighting with no false-positive alert. `icons` are deliberately excluded (their
  remote URLs churn benignly) and remain on the watch list.
- **Prebuilt release binaries** — `.github/workflows/release.yml` builds and publishes
  platform archives (Linux x86_64, Windows x86_64, macOS Apple Silicon/Intel) on every `v*` tag,
  with `SHA256SUMS`, an SPDX SBOM, and a build provenance attestation. See
  [docs/RELEASING.md](docs/RELEASING.md).

### Changed

- **MSRV corrected to Rust 1.86** (was declared 1.80, which no longer compiled the locked
  dependency tree — `idna`/`icu` require 1.86 and the lockfile carries edition-2024 manifests).
  CI now proves the declared MSRV with a dedicated `cargo check --locked` job, and runs the full
  build/test/clippy matrix on macOS in addition to Linux and Windows.

## [0.1.0] - 2026-07-09

First public release. mcpglass is a transparent proxy — a single Rust binary — that sits between an
AI client and its MCP servers for debugging, observability, auditing, and security. All data stays
on the local machine.

### Added

- **Transparent stdio interception** — `mcpglass wrap -- <server command>` runs any stdio MCP server
  with zero behavior change, tapping each direction into a local SQLite database out of band.
  Fail-open by design: no proxy-side error can alter or stall client↔server traffic.
- **HTTP (Streamable HTTP) transport** — `mcpglass gateway` runs a long-lived local reverse proxy
  for url-type MCP servers (spec 2025-06-18). JSON and SSE responses stream through untouched while
  a side-channel tap records them; loopback-only with `Origin`/`Host` validation. An unreachable
  upstream returns an honest `502` rather than a synthesized reply.
- **One-command config takeover** — `mcpglass attach [claude-code|claude-desktop|cursor|all]`
  rewrites client configs to route existing servers through the proxy (with backups); stdio servers
  are wrapped, url servers are pointed at the gateway with their upstream recorded in `gateway.toml`.
  `mcpglass detach` restores them; `--dry-run` previews.
- **Local dashboard** — `mcpglass dashboard` serves a loopback timeline of every
  request/response/notification: per-session views, filters, a payload inspector, per-method
  latency, and Security, Context, and Inject tabs.
- **Security layer** (`--policy <file>`, TOML):
  - Tool integrity pinning — fingerprints each server's tool definitions and flags changes across
    runs (rug-pull detection).
  - Secret-leak filtering — scans outgoing `tools/call` arguments for well-known credential shapes
    (AWS, GitHub, OpenAI, Anthropic, Slack, Google, PEM keys, JWTs) plus custom regexes; matches are
    masked in the audit view.
  - Per-tool allow/deny lists with prefix wildcards, and an append-only audit log.
  - Default **monitor** mode (observe and flag); opt-in **enforce** mode (`--enforce`) actively
    refuses denied/leaking calls with an in-protocol JSON-RPC error, never severing the connection.
- **Context-bloat analysis** — `mcpglass bloat` (and the dashboard's Context tab) estimates how many
  context tokens each server's tool schemas cost, ranks the fattest tools, and flags over-long
  descriptions. Token counts are a heuristic (~4 chars/token), not an exact tokenizer.
- **Request replay** — `mcpglass replay <message-id>` (and the dashboard's Replay button) re-sends a
  recorded client→server request out of band, re-spawning the stdio server (or re-initializing the
  HTTP upstream) and showing the response. Replay is never recorded and can trigger real side
  effects, so the dashboard asks for confirmation.
- **Fault injection** — `mcpglass wrap --inject <file>` / `mcpglass gateway --inject <file>` applies
  a TOML ruleset that simulates faults on live traffic (delay, synthetic JSON-RPC error, dropped
  frame, truncation) in either direction, for resilience testing. Off by default; injected faults
  appear in the dashboard's Inject tab. (HTTP SSE response streams are not injected in this version.)

### Security

- The proxy stays fail-open under all internal errors; the only wire-changing behaviors are explicit
  user choices (enforce blocks, configured fault injection) and startup aborts on a broken
  policy/inject config (before any byte is forwarded).
- Gateway and dashboard bind to `127.0.0.1` only and validate `Origin`/`Host` against loopback to
  defend against DNS rebinding and CSRF-to-localhost.
- **Disclosure:** the local SQLite database records full raw traffic, including any secret that flows
  through it in plaintext. This is by design (it is a traffic recorder); the data never leaves your
  machine. Secret filtering masks values only in the security audit view. See
  [SECURITY.md](SECURITY.md).

[0.1.0]: https://github.com/q86865511/mcpglass/releases/tag/v0.1.0
