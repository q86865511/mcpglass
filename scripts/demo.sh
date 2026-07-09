#!/usr/bin/env bash
# Generates a real, replayable mcpglass demo database.
#
# POSIX counterpart to scripts/demo.ps1. Same behavior: drives a scripted MCP
# conversation against @modelcontextprotocol/server-filesystem through
# `mcpglass wrap`, once cleanly and once with fault injection (--inject), so
# the dashboard has real traffic for screenshots/GIF recording.
#
# Idempotent: wipes and rebuilds its own scratch directory under $TMPDIR (or
# /tmp) on every run.
#
# NOTE: developed and exercised on Windows (this repo's primary target); this
# POSIX port has NOT been run on macOS/Linux. It mirrors demo.ps1 line for
# line and should work, but treat it as best-effort until verified there.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
assets_dir="$script_dir/demo-assets"
client_script="$assets_dir/mcp-client.js"
inject_toml="$assets_dir/inject.toml"

# --- locate the mcpglass binary ---------------------------------------------
release_bin="$repo_root/target/release/mcpglass"
debug_bin="$repo_root/target/debug/mcpglass"
if [ -x "$release_bin" ]; then
  mcpglass_exe="$release_bin"
elif [ -x "$debug_bin" ]; then
  mcpglass_exe="$debug_bin"
else
  echo "error: mcpglass binary not found. Build it first: cargo build --workspace (or --release --workspace)." >&2
  exit 1
fi
echo "Using mcpglass binary: $mcpglass_exe"

# --- check node/npx are on PATH ---------------------------------------------
if ! command -v node >/dev/null 2>&1; then
  echo "error: node is required to drive the demo MCP client (it plays the AI client's role)." >&2
  exit 1
fi
if ! command -v npx >/dev/null 2>&1; then
  echo "error: npx is required to run the demo MCP server (@modelcontextprotocol/server-filesystem)." >&2
  exit 1
fi

# --- scratch workspace: outside the repo, wiped each run for idempotency ---
demo_root="${TMPDIR:-/tmp}/mcpglass-demo"
rm -rf "$demo_root"
mkdir -p "$demo_root/files"

printf 'Hello from the mcpglass demo!\n' > "$demo_root/files/sample.txt"
printf '# Demo notes\nSecond line for read_text_file to show.\n' > "$demo_root/files/notes.md"

db_path="$demo_root/sessions.db"
log_path="$demo_root/mcpglass.log"

echo ""
echo "=== Pass 1/2: clean traffic (no fault injection) ==="
node "$client_script" "$mcpglass_exe" "$db_path" "$log_path" "none" "$demo_root/files" "demo-filesystem"

echo ""
echo "=== Pass 2/2: fault-injected traffic (--inject $inject_toml) ==="
node "$client_script" "$mcpglass_exe" "$db_path" "$log_path" "$inject_toml" "$demo_root/files" "demo-filesystem-inject"

echo ""
echo "=== Context bloat report (proves messages + tool fingerprints landed) ==="
"$mcpglass_exe" bloat --db "$db_path"

echo ""
echo "Demo database ready: $db_path"
echo "Next steps:"
echo "  $mcpglass_exe dashboard --db \"$db_path\""
echo "  (then open the Sessions / Messages / Inject tabs for the two demo-filesystem* sessions)"
