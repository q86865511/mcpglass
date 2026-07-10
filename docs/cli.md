# CLI reference

`mcpglass` has seven subcommands. Run `mcpglass <command> --help` for the authoritative flag list;
this page summarizes each command with common flags and examples.

Unless overridden, all commands share a data directory under your OS-local data path
(`<data_local>/mcpglass/`): `sessions.db` (the SQLite recording), `mcpglass.log` (proxy
diagnostics), `policy.toml` (default policy, if present), and `gateway.toml` (upstream routes,
written by `attach`).

---

## `wrap`

Run a single stdio MCP server through the proxy. mcpglass spawns the server as a child, wires stdio
byte-for-byte, and taps each direction into SQLite out of band. This is the interception primitive
that `attach` wires up for you; you rarely run it by hand.

| Flag | Default | Meaning |
|------|---------|---------|
| `--db <path>` | `<data_local>/mcpglass/sessions.db` | SQLite session file. |
| `--log <path>` | `<data_local>/mcpglass/mcpglass.log` | Proxy diagnostics log (never written to stdout/stderr, which are the protocol channels). |
| `--name <label>` | wrapped program's name | Human-friendly session label. |
| `--policy <path>` | `<data_local>/mcpglass/policy.toml` if present, else built-in monitor-only | Security policy file (see [configuration.md](configuration.md)). |
| `--enforce` | off | Force enforce mode regardless of the policy file's `mode`. The only mode that can block a request. |
| `--inject <path>` | off | Fault-injection config (see [configuration.md](configuration.md)). |
| `-- <cmd> [args...]` | *(required)* | The server command and its args, after `--`. |

```sh
# Wrap a git MCP server, monitor-only.
mcpglass wrap -- npx -y @modelcontextprotocol/server-git

# Wrap with an explicit policy in enforce mode.
mcpglass wrap --policy ./policy.toml --enforce -- uvx mcp-server-fetch
```

**Notes.** A policy or inject file that exists but fails to parse aborts startup before any byte is
forwarded (a security/testing config must not silently fail open). `wrap` mirrors the child's exit
code.

---

## `attach`

Rewrite a client's MCP config so its existing servers route through mcpglass. stdio servers are
wrapped with `mcpglass wrap`; url-type servers are repointed at the gateway
(`http://127.0.0.1:<gateway-port>/u/<name>`) with their real upstream recorded in `gateway.toml`. A
backup of each config is written before it is changed. Reverse it with `detach`.

| Argument / flag | Default | Meaning |
|-----------------|---------|---------|
| `target` (positional) | `all` | Which client(s) to rewrite: `claude-code`, `claude-desktop`, `cursor`, or `all` (only touches configs it finds). |
| `--project <dir>` | — | For `claude-code`, rewrite `<dir>/.mcp.json` instead of the user config. |
| `--dry-run` | off | Print the intended changes without writing or backing up. |
| `--gateway-port <port>` | `7412` | Port `mcpglass gateway` listens on; url servers are repointed there. Must match the port you run `gateway` with. |

```sh
mcpglass attach claude-code --dry-run   # preview
mcpglass attach claude-code             # apply
mcpglass attach all                     # every client found
```

**Notes.** When you name a single client explicitly and its config is corrupt/unreadable, `attach`
exits non-zero (a script driving it needs to see the failure). In `all` mode an unreadable config is
skipped and the run still exits 0. A write failure is always non-zero.

---

## `detach`

Reverse `attach`: wrapped stdio entries are unwrapped back to their original command/args, and
url entries are re-pointed at the upstream recorded in `gateway.toml`. (The timestamped backups
`attach` writes are a manual safety net — `detach` does not read them, so keep `gateway.toml`
around until every url server is detached.)

| Argument / flag | Default | Meaning |
|-----------------|---------|---------|
| `target` (positional) | `all` | Which client(s) to restore. |
| `--project <dir>` | — | For `claude-code`, restore `<dir>/.mcp.json` instead of the user config. |
| `--dry-run` | off | Print the intended changes without writing. |

```sh
mcpglass detach claude-code
mcpglass detach all
```

**Notes.** Same exit-code semantics as `attach`: an explicitly-named corrupt target exits non-zero,
`all` mode skips it and stays 0.

---

## `dashboard`

Serve the local HTTP dashboard: a timeline of every recorded request/response/notification, with
per-session views, filters, a payload inspector, per-method latency, and Security, Context, and
Inject tabs.

| Flag | Default | Meaning |
|------|---------|---------|
| `--db <path>` | `<data_local>/mcpglass/sessions.db` | SQLite session file to read. |
| `--port <port>` | `7411` | Port to listen on. |
| `--no-open` | off | Skip opening a browser tab automatically. |

```sh
mcpglass dashboard                 # opens http://127.0.0.1:7411
mcpglass dashboard --port 8080 --no-open
```

**Notes.** The dashboard binds to loopback only and validates the `Origin`/`Host` of every request
(it has a mutating `replay` endpoint, so this guards against DNS-rebinding / CSRF-to-localhost). The
Inject tab reads `GET /api/sessions/{id}/inject` and lists any fault-injection events for the
session.

---

## `gateway`

Run the long-lived reverse proxy for url-type (Streamable HTTP, spec through 2025-11-25) MCP
servers. JSON
and SSE responses stream through untouched while a side-channel tap records them; policy decisions
apply per request. `attach` repoints url servers at this gateway.

| Flag | Default | Meaning |
|------|---------|---------|
| `--port <port>` | `7412` | Port to listen on (must match `attach --gateway-port`). |
| `--db <path>` | `<data_local>/mcpglass/sessions.db` | SQLite session file. |
| `--log <path>` | `<data_local>/mcpglass/mcpglass.log` | Proxy diagnostics log. |
| `--policy <path>` | same resolution as `wrap` | Security policy file. |
| `--enforce` | off | Force enforce mode. |
| `--inject <path>` | off | Fault-injection config (same format as `wrap --inject`). |
| `--upstream <name=url>` | from `gateway.toml` | Upstream route, repeatable. If omitted, routes are read from `<data_local>/mcpglass/gateway.toml` (written by `attach`). |

```sh
# Explicit route, no attach needed.
mcpglass gateway --upstream ctx7=https://mcp.context7.com/mcp

# Use the routes attach recorded in gateway.toml.
mcpglass gateway
```

**Notes.** The gateway binds to `127.0.0.1` only and validates `Origin`/`Host` against loopback. If
an upstream is unreachable it honestly returns `502` rather than synthesizing a fake JSON-RPC reply.
Startup aborts on a broken policy/inject file (before binding, so no traffic is affected). SSE
response streams are not fault-injected in this version.

---

## `replay`

Re-send a recorded client→server request back to its server, out of band. A debugging probe, not a
wire path: it reconstructs the server from the recorded session, drives a fresh `initialize`
handshake, and prints the response.

| Argument / flag | Default | Meaning |
|-----------------|---------|---------|
| `message-id` (positional) | *(required)* | The id of the client→server **request** message to replay (from the dashboard or the sessions db). Responses, notifications, and server→client frames are rejected. |
| `--db <path>` | `<data_local>/mcpglass/sessions.db` | SQLite session file. |
| `--timeout-secs <n>` | `30` | Overall time budget for the whole replay exchange. |

```sh
mcpglass replay 4213
mcpglass replay 4213 --timeout-secs 60
```

**Notes.** stdio replay **re-spawns the server process**, so replaying a request can trigger real
side effects (a write, a delete, an outbound call). The replay itself is never recorded. In the
dashboard, the Replay button asks for confirmation before running for this reason.

---

## `bloat`

Context-bloat analysis: estimate how many context tokens a session's advertised tool catalog costs,
and flag the heaviest tools worth trimming.

| Flag | Default | Meaning |
|------|---------|---------|
| `--db <path>` | `<data_local>/mcpglass/sessions.db` | SQLite session file. |
| `--session <n>` | most recently started session | Which session to analyze. |
| `--top <n>` | `10` | How many of the heaviest tools to list. |

```sh
mcpglass bloat
mcpglass bloat --session 12 --top 20
```

**Notes.** Token counts are a **zero-dependency heuristic** (~4 characters per token), always
labelled approximate — never a real tokenizer count. Use it for relative comparison ("which tools
are fattest"), not exact billing figures. It records no traffic; note that opening a database created by an older mcpglass may still apply an additive schema upgrade.
