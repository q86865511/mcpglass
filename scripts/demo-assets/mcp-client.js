#!/usr/bin/env node
// Demo MCP client used by scripts/demo.ps1 / scripts/demo.sh.
//
// Plays a scripted JSON-RPC conversation (initialize -> tools/list ->
// 4x tools/call) against a real MCP server (the official
// @modelcontextprotocol/server-filesystem package), routed through
// `mcpglass wrap`. There is no AI client involved: this script *is* the
// client, so the resulting sessions.db has real, inspectable traffic for
// the dashboard without needing an actual LLM in the loop.
//
// Usage:
//   node mcp-client.js <mcpglassExe> <dbPath> <logPath> <injectTomlOrNone> <filesDir> <sessionLabel>
//
// Exit 0 if every request got a response (a JSON-RPC error response still
// counts as "got a response" -- that's the point of the --inject pass).
// Exit 1 on spawn failure or if any request times out.

const { spawn } = require("child_process");
const path = require("path");

const [, , mcpglassExe, dbPath, logPath, injectPath, filesDir, sessionLabel] = process.argv;

if (!mcpglassExe || !dbPath || !logPath || !injectPath || !filesDir || !sessionLabel) {
  console.error(
    "usage: mcp-client.js <mcpglassExe> <dbPath> <logPath> <injectTomlOrNone> <filesDir> <sessionLabel>"
  );
  process.exit(1);
}

const REQUEST_TIMEOUT_MS = 8000;

const args = ["wrap", "--db", dbPath, "--log", logPath, "--name", sessionLabel];
if (injectPath !== "none") {
  args.push("--inject", injectPath);
}
args.push("--", "npx", "-y", "@modelcontextprotocol/server-filesystem", filesDir);

console.log(`[client] spawning: ${mcpglassExe} ${args.join(" ")}`);
const child = spawn(mcpglassExe, args, { stdio: ["pipe", "pipe", "pipe"] });

let spawnFailed = false;
child.on("error", (e) => {
  spawnFailed = true;
  console.error(`[client] spawn error: ${e.message}`);
});

// The wrapped server's own diagnostics (npx download progress, the
// filesystem server's startup banner) land on stderr, passed through
// unmodified by mcpglass. Surface them for troubleshooting.
child.stderr.on("data", (d) => process.stderr.write(`[server] ${d}`));

// mcpglass's stdout is the protocol channel: one JSON-RPC message per line.
let stdoutBuf = "";
const pending = new Map(); // id -> resolve fn

child.stdout.on("data", (d) => {
  stdoutBuf += d.toString();
  let idx;
  while ((idx = stdoutBuf.indexOf("\n")) !== -1) {
    const line = stdoutBuf.slice(0, idx);
    stdoutBuf = stdoutBuf.slice(idx + 1);
    if (!line.trim()) continue;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      console.error(`[client] non-JSON line from proxy, ignoring: ${line}`);
      continue;
    }
    if (msg.id !== undefined && msg.id !== null && pending.has(msg.id)) {
      const resolve = pending.get(msg.id);
      pending.delete(msg.id);
      resolve(msg);
    }
  }
});

function send(obj) {
  child.stdin.write(JSON.stringify(obj) + "\n");
}

function request(id, method, params) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`timed out waiting for response id=${id} (${method})`));
    }, REQUEST_TIMEOUT_MS);
    pending.set(id, (msg) => {
      clearTimeout(timer);
      resolve(msg);
    });
    send({ jsonrpc: "2.0", id, method, params });
  });
}

function notify(method, params) {
  send({ jsonrpc: "2.0", method, params });
}

function describe(resp) {
  return resp.error ? `error: ${resp.error.message}` : "ok";
}

async function main() {
  const initResp = await request(1, "initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "mcpglass-demo-client", version: "1.0" },
  });
  console.log(`[client] initialize -> ${describe(initResp)}`);

  notify("notifications/initialized", {});

  const listResp = await request(2, "tools/list", {});
  const toolCount = listResp.result?.tools?.length ?? 0;
  console.log(`[client] tools/list -> ${toolCount} tool(s)`);

  const sample = path.join(filesDir, "sample.txt");
  const outFile = path.join(filesDir, "demo-output.txt");

  const call1 = await request(3, "tools/call", {
    name: "list_directory",
    arguments: { path: filesDir },
  });
  console.log(`[client] tools/call list_directory -> ${describe(call1)}`);

  const call2 = await request(4, "tools/call", {
    name: "read_text_file",
    arguments: { path: sample },
  });
  console.log(`[client] tools/call read_text_file -> ${describe(call2)}`);

  const call3 = await request(5, "tools/call", {
    name: "write_file",
    arguments: { path: outFile, content: "written by the mcpglass demo\n" },
  });
  console.log(`[client] tools/call write_file -> ${describe(call3)}`);

  const call4 = await request(6, "tools/call", {
    name: "get_file_info",
    arguments: { path: outFile },
  });
  console.log(`[client] tools/call get_file_info -> ${describe(call4)}`);
}

// Close stdin and let the proxy exit on its own so it can flush storage;
// only kill it if it hasn't exited after a generous grace period.
function shutdown(code) {
  child.stdin.end();
  const fallback = setTimeout(() => {
    child.kill();
    process.exit(code);
  }, 5000);
  child.once("exit", () => {
    clearTimeout(fallback);
    process.exit(code);
  });
}

main()
  .then(() => {
    console.log("[client] scripted conversation complete");
    shutdown(spawnFailed ? 1 : 0);
  })
  .catch((e) => {
    console.error(`[client] FAILED: ${e.message}`);
    shutdown(1);
  });
