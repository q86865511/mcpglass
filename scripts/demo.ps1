#requires -Version 5.1
<#
.SYNOPSIS
    Generates a real, replayable mcpglass demo database.

.DESCRIPTION
    Drives a scripted MCP conversation (initialize -> tools/list -> 4x
    tools/call) against the real @modelcontextprotocol/server-filesystem
    package through `mcpglass wrap`, once cleanly and once with fault
    injection (--inject), so the dashboard has real traffic to show for
    screenshots and GIF recording. No AI client or manual clicking required.

    Idempotent: every run wipes and rebuilds its own scratch directory under
    $env:TEMP, so re-running never accumulates stale state or touches the
    repo or the user's real mcpglass data directory.

.EXAMPLE
    powershell -File scripts\demo.ps1
#>

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$assetsDir = Join-Path $PSScriptRoot "demo-assets"
$clientScript = Join-Path $assetsDir "mcp-client.js"
$injectToml = Join-Path $assetsDir "inject.toml"

# --- locate the mcpglass binary ---------------------------------------------
$releaseExe = Join-Path $repoRoot "target\release\mcpglass.exe"
$debugExe = Join-Path $repoRoot "target\debug\mcpglass.exe"
if (Test-Path $releaseExe) {
    $mcpglassExe = $releaseExe
} elseif (Test-Path $debugExe) {
    $mcpglassExe = $debugExe
} else {
    Write-Error "mcpglass binary not found. Build it first: cargo build --workspace (or --release --workspace)."
    exit 1
}
Write-Host "Using mcpglass binary: $mcpglassExe"

# --- check node/npx are on PATH ---------------------------------------------
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Error "node is required to drive the demo MCP client (it plays the AI client's role). Install Node.js and retry."
    exit 1
}
if (-not (Get-Command npx -ErrorAction SilentlyContinue)) {
    Write-Error "npx is required to run the demo MCP server (@modelcontextprotocol/server-filesystem). Install Node.js/npm and retry."
    exit 1
}

# --- scratch workspace: outside the repo, wiped each run for idempotency ---
$demoRoot = Join-Path $env:TEMP "mcpglass-demo"
if (Test-Path $demoRoot) {
    Remove-Item -Recurse -Force $demoRoot
}
New-Item -ItemType Directory -Force -Path $demoRoot | Out-Null

$filesDir = Join-Path $demoRoot "files"
New-Item -ItemType Directory -Force -Path $filesDir | Out-Null
[System.IO.File]::WriteAllText((Join-Path $filesDir "sample.txt"), "Hello from the mcpglass demo!`n")
[System.IO.File]::WriteAllText((Join-Path $filesDir "notes.md"), "# Demo notes`nSecond line for read_text_file to show.`n")

$dbPath = Join-Path $demoRoot "sessions.db"
$logPath = Join-Path $demoRoot "mcpglass.log"

Write-Host ""
Write-Host "=== Pass 1/2: clean traffic (no fault injection) ==="
& node $clientScript $mcpglassExe $dbPath $logPath "none" $filesDir "demo-filesystem"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Clean traffic pass failed (exit $LASTEXITCODE). Check the log: $logPath"
    exit 1
}

Write-Host ""
Write-Host "=== Pass 2/2: fault-injected traffic (--inject $injectToml) ==="
& node $clientScript $mcpglassExe $dbPath $logPath $injectToml $filesDir "demo-filesystem-inject"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Inject traffic pass failed (exit $LASTEXITCODE). Check the log: $logPath"
    exit 1
}

Write-Host ""
Write-Host "=== Context bloat report (proves messages + tool fingerprints landed) ==="
& $mcpglassExe bloat --db $dbPath

Write-Host ""
Write-Host "Demo database ready: $dbPath"
Write-Host "Next steps:"
Write-Host "  $mcpglassExe dashboard --db `"$dbPath`""
Write-Host "  (then open the Sessions / Messages / Inject tabs for the two demo-filesystem* sessions)"
