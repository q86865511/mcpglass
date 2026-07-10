# Security model

mcpglass sits directly on the wire between your AI client and your MCP servers. That position is
powerful and dangerous, so its design starts from one non-negotiable rule and adds security features
that never violate it.

## Fail-open is the iron rule

**While the mcpglass process is alive, no failure in its own machinery may block or delay
client↔server traffic.** A parse failure, a full or broken database, a panic in the policy engine,
an unknown JSON-RPC field — all of these forward the bytes unchanged. Recording, fingerprinting and
security-event persistence are strictly best-effort side channels: a full channel or a failed write
drops the record, never the frame. The proxy would rather leak an un-inspectable frame than stall
or drop your session. Concretely:

- Forwarding always happens **before** recording. The tap (SQLite writes, fingerprinting) is
  strictly best-effort and off the hot path; a stalled storage thread drops tap events (logging the
  first drop only) rather than back-pressuring the wire.
- Unknown / future JSON-RPC fields pass through verbatim.
- Over-HTTP: if an upstream is unreachable the gateway honestly returns `502` — it never synthesizes
  a fake JSON-RPC reply impersonating the server. Tap/policy failures never alter or delay bytes
  already flowing.

**What this guarantee does not cover: process-level failure.** mcpglass sits on the wire, so if its
process dies — an OOM kill, `kill -9`, a host crash, an OS-level pipe failure — the connection it
carries is severed, exactly as it would be for any proxy. The fail-open promise is about the code
paths *inside* a live process (they can fail without touching the wire), not about the process
itself being unkillable.

### The deliberate exceptions

Fail-open governs *proxy bugs*. A few behaviors change the wire on purpose, because the user
explicitly asked for them:

1. **Config load failure at startup** — a `--policy` or `--inject` file that is passed but fails to
   load aborts startup. Safe because it happens *before any byte is forwarded*; a security/testing
   config must not silently do nothing.
2. **An enforce-mode policy hit** — an explicit deny/secret match in `enforce` mode returns an
   in-protocol JSON-RPC error (`-32001`) to the client instead of forwarding. This is a legal
   protocol response, not a severed connection.
3. **A configured `--inject` fault** — a user-requested, in-protocol intervention (delay / error /
   drop / truncate), the same class as an enforce block.

Even within these, the *machinery* stays fail-open: an injector lock-poisoning or panic forwards
normally, and a failed event/record write never changes what is on the wire.

## Monitor vs enforce

The default posture is **monitor**: mcpglass observes and flags but never blocks. Every policy
finding is recorded as a security event (visible in the dashboard's Security tab) while the request
forwards untouched.

**Enforce** (`--enforce`, or `mode = "enforce"` in the policy file) is opt-in and is the only mode
that can refuse a request. On a deny/secret match it withholds the frame from the server and returns
a JSON-RPC error to the client — it never drops the connection, and any proxy-internal error still
fails open to forwarding.

## Security features

Security decisions are split by direction:

- **Client→server (c2s)** is a **synchronous, blocking, pure decision** (`policy::evaluate_request`)
  — the one place a request can be withheld, and only in enforce mode.
- **Server→client (s2c)** stays a **bypass tap**: fingerprint comparison runs on the storage thread
  and only ever raises alerts, never blocks.

### Tool integrity pinning (rug-pull detection)

mcpglass fingerprints each server's tool definitions (name + description + input schema +
annotations, canonicalized and SHA-256'd) and compares every `tools/list` response against the
recorded history for that server — **across runs**. A server that silently rewrites a tool's
description or schema after you approved it raises a `fingerprint_change` event. This catches the
"rug-pull": benign tools that mutate into malicious ones after trust is established.

### Secret-leak filtering

When `secret_scan` is on (the default), mcpglass scans the `arguments` of outgoing `tools/call`
requests for well-known credential shapes — AWS access keys, GitHub PATs, Anthropic/OpenAI keys,
Slack tokens, Google API keys, PEM private keys, JWTs — plus any `custom_secret_patterns` you add.
In monitor mode a match is flagged; in enforce mode it blocks the call. Only `arguments` are scanned
(never the tool name or advertised schema), and matched values are **masked** in the security event
detail (first 4 / last 2 characters) — the audit view never shows the raw secret.

### Per-tool allow/deny and audit log

Tools can be allow-listed or deny-listed by name. Deny wins, and only the deny list accepts a
trailing `*` prefix wildcard — allow-list entries are exact matches.
Every decision — forwarded or blocked — is written to an append-only audit log, surfaced in the
dashboard's Security tab.

## Data locality and disclosure

**Everything stays on your machine.** mcpglass writes to a local SQLite file and serves a
loopback-only dashboard; nothing is sent anywhere.

**Full disclosure:** that SQLite database records **full raw traffic**, including any secret that
flows through it in plaintext. This is by design — it is a traffic recorder, and masking the wire
would defeat the debugging purpose. Secret filtering masks values only in the *security audit view*;
the underlying message payloads are stored verbatim. Treat the sessions database as sensitive: it
can contain API keys, tokens, and any private data your tool calls carried.

### Data at rest

The sessions database and the proxy log are treated as sensitive on disk:

- **Unix:** both files are created (and, if they already exist, reset) to owner-only `0600`
  permissions. Because SQLite matches the mode of its `-wal`/`-shm` sidecars to the main database
  file, restricting the main file also restricts them. This is best-effort — a permission failure
  never blocks opening the file (fail-open).
- **Windows:** the default `%LOCALAPPDATA%` ACL already limits these files to the current user, so no
  additional ACL work is done.

### Managing recorded data

You are not stuck recording everything forever:

- **Record less up front.** `wrap`/`gateway` take `--record metadata` (keep method/ids/timing/size
  but drop the raw bodies) or `--record off` (record nothing to `messages`). Security and inject
  events are always recorded regardless — the security promise is independent of recording.
- **Delete after the fact.** `mcpglass prune` drops sessions by age (`--older-than`) or to a size cap
  (`--max-size`); the dashboard has a per-session delete button. Both keep tool fingerprints (the
  cross-session rug-pull baseline).
- **Share safely.** `mcpglass export` writes a single session to a JSON bundle with every body and
  argv token run through the secret masker — there is no un-masked export (share the db file itself
  if you truly need raw data).

## Network hardening (DNS rebinding / CSRF-to-localhost)

Both the gateway and the dashboard bind to `127.0.0.1` only. Because both expose mutating endpoints
(the gateway proxies requests; the dashboard has `POST /api/messages/{id}/replay`), every request passes a loopback
middleware that validates the `Origin` and `Host` headers resolve to loopback. This blocks a
malicious web page in your browser from reaching the local proxy via DNS rebinding or a
CSRF-to-localhost attack.
