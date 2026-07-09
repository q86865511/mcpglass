# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately**, not through public issues.

Use GitHub's private vulnerability reporting for this repository:

1. Go to the [Security tab](https://github.com/q86865511/mcpglass/security) of the repository.
2. Click **Report a vulnerability** to open a private security advisory.

Please include enough detail to reproduce — affected version/commit, platform, configuration, and a
minimal repro if possible. We aim to acknowledge reports promptly and will coordinate a fix and
disclosure timeline with you. Please give us reasonable time to release a fix before any public
disclosure.

Since mcpglass is early-stage software with no prebuilt binaries yet, there is no formal support
window; fixes land on `master` and in the next release.

## Data handling and disclosure

mcpglass is a **local traffic recorder**, and one property of its design is important enough to state
plainly as a security consideration:

- **The local SQLite session database (`<data_local>/mcpglass/sessions.db` by default) stores full
  raw MCP traffic in plaintext**, including any API keys, tokens, or private data that flow through
  your tool calls. This is intentional — masking the wire would defeat the debugging and auditing
  purpose. The secret-scanning feature masks values only in the *security audit view*; the
  underlying message payloads are recorded verbatim.
- **All data stays on your machine.** mcpglass makes no outbound network calls with your traffic; the
  gateway and dashboard bind to `127.0.0.1` only and validate `Origin`/`Host` against loopback to
  resist DNS-rebinding / CSRF-to-localhost.

Treat the sessions database as sensitive. If you share it (for a bug report, say), scrub it first —
it may contain credentials. Store it with appropriate filesystem permissions, and delete sessions
you no longer need.

For the full threat model and the fail-open design, see
[docs/security-model.md](docs/security-model.md).
