# Configuration

mcpglass has two optional TOML config files, each enabled by a flag on `wrap`/`gateway`:

- **Security policy** (`--policy`) — allow/deny tools, scan for secrets, pin tool fingerprints.
- **Fault injection** (`--inject`) — simulate faults on live traffic to test resilience.

Both are validated at startup. A file that is passed but fails to load (missing, unreadable, bad
TOML, unknown key, invalid regex/probability) **aborts startup before any byte is forwarded**. This
is a deliberate exception to the fail-open rule: aborting is only safe here because no traffic has
flowed yet, and a security/testing config that silently does nothing is worse than one that refuses
to start. Both loaders use `deny_unknown_fields`, so a typo'd key (e.g. `deney` instead of `deny`)
is a hard error rather than a silently-ignored rule.

---

## Policy TOML

Passed with `mcpglass wrap --policy <file>` or `mcpglass gateway --policy <file>`. If `--policy` is
omitted, mcpglass loads `<data_local>/mcpglass/policy.toml` when it exists, otherwise a built-in
monitor-only default.

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `mode` | `"monitor"` \| `"enforce"` | `"monitor"` | `monitor` observes and flags but never blocks; `enforce` is the only mode that can refuse a request. `--enforce` on the CLI overrides this. |
| `allow` | list of strings | `[]` | Tool-name allow-list. When **non-empty**, any `tools/call` whose tool is not listed is treated as a deny. Exact match only. |
| `deny` | list of strings | `[]` | Tool-name deny-list; takes **priority over `allow`**. A trailing `*` is a prefix wildcard (`dangerous_*` matches `dangerous_rm`); otherwise the match is exact. |
| `secret_scan` | bool | `true` | Scan `tools/call` arguments for secrets (built-in credential shapes + your custom patterns). |
| `custom_secret_patterns` | list of regex strings | `[]` | Extra secret regexes, reported as `custom[i]`. An invalid regex fails at load. |

Secret scanning covers only `params.arguments` of a `tools/call` (recursing into nested strings) —
never the method name or a tool's advertised schema, which keeps a tool merely *named* like a token
from tripping a false positive. Built-in patterns: AWS access keys, GitHub classic + fine-grained
PATs, Anthropic keys, OpenAI keys, Slack tokens, Google API keys, PEM private keys, and JWTs.
Matched values are **masked** (first 4 / last 2 characters, middle starred) everywhere they are
recorded.

### Example `policy.toml`

```toml
# Enforce mode actively refuses denied / secret-leaking tools/call requests by
# returning an in-protocol JSON-RPC error to the client (it never drops the
# connection). Remove this line (or set "monitor") to only observe and flag.
mode = "enforce"

# When non-empty, ONLY these tools are allowed; everything else is denied.
# Leave empty to allow all tools except those matched by `deny`.
allow = ["read_file", "list_directory", "search"]

# Deny-list wins over allow. Trailing `*` is a prefix wildcard.
deny = ["delete_*", "exec"]

# Scan tools/call arguments for credentials (default true).
secret_scan = true

# Extra secret shapes specific to your org, on top of the built-ins.
custom_secret_patterns = ["MYCORP_[A-Z0-9]{20}"]
```

---

## Inject TOML

Passed with `mcpglass wrap --inject <file>` or `mcpglass gateway --inject <file>`. Off by default —
there is no default path and no injection unless you pass the flag. Fault injection is a deliberate,
in-protocol intervention for testing server resilience and client fault-tolerance; it is not a
fail-open violation (the injection *machinery* still fails open — a poisoned lock or panic forwards
normally, and a failed event write never changes the wire).

Top-level:

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `seed` | u64 | clock-derived | Fixes the RNG for reproducible runs. With no `seed`, separate runs vary. |
| `rules` | array of tables (`[[rules]]`) | `[]` | The ordered rule list. Rules are considered in file order; the first eligible rule that rolls a hit wins. |

Each `[[rules]]`:

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `direction` | `"c2s"` \| `"s2c"` | *(required)* | `c2s` = client→server, `s2c` = server→client. |
| `method` | string | absent = any | Method filter. A trailing `*` is a prefix wildcard (`tools/*`). A rule with a `method` filter never matches a frame that has no method (a response or non-JSON line). |
| `probability` | float in `[0, 1]` | `1.0` | Chance the rule fires when eligible. `1.0` always fires and draws no random number. Out-of-range values fail at load. |
| `max_triggers` | u64 | unlimited | Stop firing this rule after N hits; a later eligible rule can then take over. |
| `fault` | inline table | *(required)* | The fault to inject (below). |

Fault variants (tagged on `type`; unknown fields inside the fault table are rejected — so `bytes`
on a `delay` fault, or a typo'd key, fails at load):

| `type` | Extra fields | Effect |
|--------|--------------|--------|
| `"delay"` | `delay_ms` (u64) | Sleep `delay_ms` before forwarding the frame unchanged. |
| `"error"` | `code` (i64), `message` (string) | Withhold the frame; answer the peer with a synthesized JSON-RPC error carrying the frame's id. (For a frame with no id the transports currently differ: stdio sends nothing, while the HTTP gateway answers with an error carrying `id: null` — a known asymmetry.) |
| `"drop"` | — | Withhold the frame entirely (no forward, no synthesized reply). |
| `"truncate"` | `bytes` (usize) | Forward only the first `bytes` bytes — a deliberately corrupt frame. |

The original frame is still recorded in the timeline (it genuinely was sent/emitted); injection only
changes what the *peer* receives. Injected faults also appear in the dashboard's Inject tab.

### Example `inject.toml`

```toml
seed = 42                       # optional; fix for reproducible test runs

# Add 200ms latency to every tools/call, 25% of the time, at most 5 times.
[[rules]]
direction = "c2s"
method = "tools/call"
probability = 0.25
max_triggers = 5
fault = { type = "delay", delay_ms = 200 }

# Fail every server->client response with a synthetic error.
[[rules]]
direction = "s2c"
fault = { type = "error", code = -32000, message = "injected failure" }

# Occasionally drop a client request outright.
[[rules]]
direction = "c2s"
probability = 0.1
fault = { type = "drop" }

# Truncate server frames matching tools/* to 16 bytes (a corrupt message).
[[rules]]
direction = "s2c"
method = "tools/*"
fault = { type = "truncate", bytes = 16 }
```

> Note: HTTP SSE response streams are not fault-injected in this version.
