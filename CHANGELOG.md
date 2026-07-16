# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-07-16

### Added

- **Dashboard visual overhaul (oscilloscope theme)** — the embedded React dashboard was rebuilt on a
  CSS design-token system with a dark and a light theme (follows `prefers-color-scheme`, remembers
  your choice). The two message directions read as scope channels (c2s = CH1, s2c = CH2) throughout
  the timeline, detail panel, and stats. The layout is responsive: below 900px the session sidebar
  becomes an off-canvas drawer, and below 600px the table sheds its lower-priority columns.
- **Dashboard data lifecycle UI** — the CLI-only prune and export flows are now in the dashboard:
  - `POST /api/prune` deletes sessions by age and/or to a size cap, with a dry-run preview so the
    prune dialog can show how many sessions and messages it would remove before you confirm. Tool
    fingerprints are never pruned.
  - `GET /api/sessions/{id}/export` (and the timeline's EXPORT button) downloads the same
    secret-masked JSON bundle as `mcpglass export`; there is no un-masked path.
  - `GET /api/health` now reports build capabilities, so the Replay button is disabled up front when
    the running binary has no replay backend instead of failing only on click.
- **Dashboard UX** — toast notifications for copy/replay/delete, a confirm dialog (replacing the
  browser's native `confirm`) for destructive actions, loading skeletons, deep-linkable URLs
  (`#/s/{id}/{view}?msg=`), debounced search, and keyboard navigation (`j`/`k` to move between
  frames, `/` to focus search, `Esc` to close). Auto-refresh now defaults on at a 3s interval and
  pauses while the tab is hidden.
- **`mcpglass dashboard --policy <file>`** — the dashboard's export endpoint loads the same policy
  (including custom secret patterns) as the CLI; without the flag it uses the built-in patterns.

### Changed

- The dashboard's auto-refresh default changed from off to on (3s), and the poll now pauses while the
  browser tab is backgrounded.

## [0.2.0] - 2026-07-13

### Added

- **Performance benchmarks and fail-open regression tests** — the fail-open promise is now backed by
  numbers and by tests, not just prose ([docs/benchmarks.md](docs/benchmarks.md)):
  - criterion micro-benchmarks for the hot paths (`parse_line`, `evaluate_request`, tool
    fingerprinting) and an end-to-end `wrap` overhead benchmark across `--record off|metadata|full`
    (+ `--enforce`) versus a no-proxy baseline (`cargo test -p cli --release --test bench_e2e --
    --ignored`).
  - two regression tests in the normal suite prove a stalled/saturated tap channel and an unwritable
    database never touch the wire (the storage failure drops records and is logged, forwarding stays
    byte-identical). The test hooks are `cfg(debug_assertions)`-only, so the storage loop and channel
    cost nothing in release builds.
  - a manual `workflow_dispatch` GitHub Actions job runs the benchmarks and uploads the results;
    numbers are hardware-relative and never gate CI.
- **Data lifecycle management** — you can now manage the recorded traffic instead of only
  accumulating it:
  - `mcpglass prune` deletes sessions by age (`--older-than 7d`) or to a size cap
    (`--max-size 500M`, oldest-first + vacuum), with `--dry-run` and `--vacuum`. Tool fingerprints
    are never pruned (they are the cross-session rug-pull baseline).
  - The dashboard sidebar has a per-session delete button (`DELETE /api/sessions/{id}`, confirmed),
    which likewise keeps fingerprints.
  - `wrap`/`gateway` take `--record full|metadata|off`: `metadata` keeps method/ids/timing and the
    original body size but drops the raw body; `off` records nothing to `messages`. Security and
    inject events are always recorded regardless.
  - `mcpglass export --session <id> --out bundle.json` writes a single session to a JSON bundle with
    every recorded body and argv token secret-masked (there is no un-masked export).
- **Sensitive files hardened at rest** — on Unix the sessions database and proxy log (and SQLite's
  `-wal`/`-shm` sidecars) are restricted to owner-only `0600`; Windows relies on the default
  `%LOCALAPPDATA%` ACL.
- **Structured server identity (schema v7)** — a session now records its server's
  identity as structured data (`program`, the full `argv` as a JSON array, `transport`,
  and a `server_id` hash) instead of relying on the joined command string. Two runs of
  the same launcher pointed at *different* projects are now distinct identities, so their
  tool fingerprints no longer share a baseline and cross-contaminate rug-pull detection.
  Environment is excluded from identity by construction and can never enter the hash.
- **Lossless replay reconstruction** — stdio replay now re-spawns the server from the
  recorded `argv` array, so arguments containing whitespace, quotes, or backslashes are
  reproduced exactly; `replay` also reads the recorded `transport` instead of sniffing
  the command. Legacy pre-v7 sessions fall back to the previous quote-aware command
  splitter.

### Changed

- **Fingerprint baselines survive the v7 upgrade** — tool-fingerprint history is now
  scoped by the structured `server_id`. On first sighting after upgrade, a baseline
  recorded under the old joined-command key is re-keyed onto the new `server_id` inside a
  single transaction, so an established rug-pull baseline is preserved (no false-positive
  alert and no silent reset). Existing v5/v6 databases upgrade in place; a nullable
  `raw_len` column is added to `messages` (reserved for a future metadata-only recording
  mode, unwritten by this release).

## [0.1.1] - 2026-07-10

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

[0.3.0]: https://github.com/q86865511/mcpglass/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/q86865511/mcpglass/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/q86865511/mcpglass/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/q86865511/mcpglass/releases/tag/v0.1.0
