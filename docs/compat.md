# Client compatibility matrix

Automated conformance tests (CI) prove protocol correctness against reference
implementations, but real clients differ in config handling, transport quirks,
and restart behavior. This checklist is run manually against real clients
before every release; results are recorded in the table at the bottom.

The steps assume a release-candidate binary on `PATH` and a scratch MCP server
configured in each client (any stdio server works; the official
`@modelcontextprotocol/server-everything` is a good default).

## Per-client checklist

Run the same five steps for each client. A client passes when every step holds.

1. **Attach.** `mcpglass attach <client> --dry-run` shows the expected rewrite,
   then `mcpglass attach <client>` applies it and reports a backup path.
2. **Exercise.** Restart the client, confirm the MCP server's tools still work
   from the client UI, and call at least one tool.
3. **Observe.** `mcpglass dashboard --no-open` — the session appears, the
   `tools/list` exchange and the tool call are recorded, message bodies are
   valid, and no unexpected error frames show up.
4. **Replay.** From the dashboard, replay the recorded tool call against the
   server and confirm a sane response (replay restarts stdio servers; use the
   scratch server, not one with side effects).
5. **Detach.** `mcpglass detach <client>` restores the original config
   (diff against the backup), and the client works again without mcpglass.

### Client names

| Client | `attach` target | Config notes |
|---|---|---|
| Claude Code | `claude-code` | Project-scoped servers: run from the project directory. |
| Claude Desktop | `claude-desktop` | Full app restart required after attach/detach. |
| Cursor | `cursor` | Reload the window after attach/detach. |

## HTTP gateway spot check

At least one client per release should also be verified through the HTTP path:

1. `mcpglass gateway --upstream test=<url>` with a streamable-HTTP server.
2. Point the client at `http://127.0.0.1:7412/u/test`.
3. Confirm tool calls work, SSE responses stream, and the session is recorded.

## Results

| Date | mcpglass | Client | Client version | OS | Result | Notes |
|---|---|---|---|---|---|---|
| _yyyy-mm-dd_ | _x.y.z_ | _client_ | _version_ | _os_ | _pass/fail_ | |
