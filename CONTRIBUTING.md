# Contributing to mcpglass

Thanks for your interest in improving mcpglass. This document covers the build/test workflow and PR
conventions.

## Prerequisites

- A [Rust toolchain](https://rustup.rs/), **1.86 or newer** (the workspace's `rust-version`), with
  the `clippy` component.
- [pnpm](https://pnpm.io/) and Node.js 20+ for the dashboard frontend.

## Build the frontend first

The dashboard frontend (`crates/dashboard/frontend/`, TypeScript + Vite) is embedded into the Rust
binary at build time via `rust-embed`. **You must build it before the Rust workspace**, or you get a
placeholder dashboard page:

```sh
cd crates/dashboard/frontend
pnpm install
pnpm build          # tsc (strict) + vite → dist/, which cargo embeds
cd ../../..
```

For frontend development, `pnpm mock` (a mock API server) alongside `pnpm dev` gives you live
reload without rebuilding the Rust binary.

## Build, test, lint

The full workspace check — this is what CI runs, and it must be green before a PR merges:

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

CI (`.github/workflows/ci.yml`) runs all three on both Ubuntu and Windows. Clippy warnings are
treated as errors (`-D warnings`), so keep the tree warning-clean.

## Pull request conventions

- Open PRs against the `master` branch.
- Write PR titles, descriptions, code comments, and all in-repo documentation in **English** (README
  and `docs/` are English; internal progress notes may be in another language).
- Keep changes focused; a PR should do one thing.
- Include tests for behavior changes. The codebase leans heavily on unit and integration tests —
  match that.
- CI must pass on both platforms before merge.

## Project layout

The workspace is split into focused crates:

- `proxy-core` — JSON-RPC parsing, framing, forwarding, SSE splitting, MCP version constants, bloat
  analysis.
- `storage` — SQLite persistence (rusqlite).
- `policy` — pure security logic (policy, secrets, fingerprints, decisions, injection rules); no IO
  on the hot path.
- `cli` — the `mcpglass` binary: subcommands, the stdio hot path, the HTTP gateway, and the
  `replay`/`bloat` out-of-band tools.
- `dashboard` — the axum server and embedded frontend.

Two design rules are load-bearing; please preserve them in any change to the wire path:

1. **Fail-open** — no proxy-internal error may block or delay client↔server traffic. Forward first,
   record second, best-effort always. See [docs/security-model.md](docs/security-model.md).
2. **Purity in `policy`** — the policy/injection crate does no IO on the hot path; decisions are pure
   functions the CLI runs off the wire.
