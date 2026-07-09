# Demo: generating traffic and recording a GIF

This page covers two things: running `scripts/demo.ps1` to populate a scratch database with real
MCP traffic, and recording that as a GIF for the README / release notes.

---

## 1. Generating demo traffic

`scripts/demo.ps1` (Windows, primary) and `scripts/demo.sh` (POSIX, best-effort port — see note
below) drive a scripted MCP conversation through `mcpglass wrap` against the real
[`@modelcontextprotocol/server-filesystem`](https://www.npmjs.com/package/@modelcontextprotocol/server-filesystem)
package. There is no AI client involved — `scripts/demo-assets/mcp-client.js` plays the client's
role, sending `initialize` → `tools/list` → four `tools/call` requests over stdin/stdout, exactly
the way Claude Desktop or Claude Code would. The result is a `sessions.db` with real,
richly-structured traffic (14 real filesystem tools, real descriptions, real responses) instead of
synthetic fixtures.

The script runs the conversation twice against the **same** database:

1. **Clean pass** (`demo-filesystem` session) — no fault injection, everything succeeds.
2. **Inject pass** (`demo-filesystem-inject` session) — with `scripts/demo-assets/inject.toml`,
   which delays the first `tools/call` by 500ms and replaces the second with a synthesized
   JSON-RPC error. This gives the dashboard's Inject tab something to show.

### Usage

```powershell
# from the repo root
cargo build --workspace   # or --release, if not already built
powershell -File scripts\demo.ps1
```

Requirements: `node`/`npx` on `PATH` (used to fetch and run the filesystem server; the script
checks for both and fails fast with a clear message if missing). Nothing else — no manual client,
no browser interaction.

The script is idempotent: it wipes and rebuilds `%TEMP%\mcpglass-demo\` (files, log, and db) on
every run, so re-running never accumulates stale sessions or leaves anything in the repo.

On success it prints a `mcpglass bloat --db <path>` report (proof that messages and tool
fingerprints landed) and the exact command to open the dashboard:

```powershell
mcpglass dashboard --db "C:\Users\<you>\AppData\Local\Temp\mcpglass-demo\sessions.db"
```

**`scripts/demo.sh`** mirrors `demo.ps1` line-for-line for macOS/Linux, but it has **not** been
exercised — only `demo.ps1` was actually run and verified on this Windows machine. Treat the `.sh`
version as best-effort until someone runs it on a POSIX box.

---

## 2. Recording a GIF

### Tool options (Windows)

1. **[ScreenToGif](https://www.screentogif.com/)** (recommended) — free, open-source, records
   directly to an editable frame timeline and exports GIF natively; no separate conversion step.
   - Capture at 12–15 fps (enough for UI interactions, keeps file size down).
   - Use the "Board" or "Recorder" mode, crop to the terminal/browser window only.
   - In the editor: trim dead time between steps, and use **File → Save As → GIF** with
     "Optimize" enabled (its built-in encoder does grayscale/color-count reduction well).

2. **OBS Studio + ffmpeg** (more control, works cross-platform) — record an MP4 with OBS (window
   capture, 1280×720 or crop to content), then convert with a two-pass palette for quality:
   ```sh
   ffmpeg -i demo.mp4 -vf "fps=12,scale=960:-1:flags=lanczos,palettegen" palette.png
   ffmpeg -i demo.mp4 -i palette.png -filter_complex "fps=12,scale=960:-1:flags=lanczos[x];[x][1:v]paletteuse" demo.gif
   ```
   This produces noticeably smaller/cleaner GIFs than a naive single-pass conversion, at the cost
   of an extra step.

For **terminal-only** clips (e.g. just the `demo.ps1` run, no browser), `asciinema` +
[`agg`](https://github.com/asciinema/agg) is a lighter alternative: `asciinema rec demo.cast`,
then `agg demo.cast demo.gif`. Skip this if the recording needs to show the browser dashboard too.

### Suggested recording script (storyboard)

Run `scripts/demo.ps1` once beforehand so `npx` has already cached the filesystem server package —
a cold `npx` download during the recording adds 10–30s of dead air.

| # | Scene | What to show | Approx. duration |
|---|-------|---------------|-------------------|
| 1 | Terminal | Run `powershell -File scripts\demo.ps1`. Let the two "Pass" headers and the bloat report scroll by. | 6–8s |
| 2 | Terminal → browser | Run the printed `mcpglass dashboard --db ...` command; browser opens. | 2s |
| 3 | Dashboard: Sessions | Show the session list with both `demo-filesystem` and `demo-filesystem-inject` rows. | 3s |
| 4 | Dashboard: Messages tab | Click the `demo-filesystem` session, scroll the Messages tab — real `tools/list`/`tools/call` JSON-RPC traffic. | 4–5s |
| 5 | Dashboard: Context tab | Switch to the Context (bloat) tab — same numbers as the CLI report, now visual (per-tool token bars). | 3s |
| 6 | Dashboard: Inject tab | Click the `demo-filesystem-inject` session, open the Inject tab — the delay and synthesized-error events from `inject.toml`. | 3–4s |
| 7 | Dashboard: Security tab | Quick pass over the Security tab (empty/monitor-only for this demo — mention in narration/caption that it lights up under a real policy, not this clip). | 2s |

Total: roughly 25–30 seconds, which keeps the GIF file size manageable. Manual steps (not
scriptable): opening ScreenToGif/OBS and starting/stopping the capture, clicking through the
dashboard tabs in steps 3–7, and running the final GIF export/optimize pass.

If a smaller, more focused clip is wanted for a README badge (as opposed to full release notes),
scenes 1+4 alone (terminal run → Messages tab) are enough to convey "real traffic, recorded
automatically."
