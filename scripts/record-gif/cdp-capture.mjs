// Drive the mcpglass dashboard in headless Edge over CDP and capture one PNG per scene.
// Usage: node cdp-demo.mjs <cdpPort> <dashboardUrl> <outDir>
const [port, url, outDir] = process.argv.slice(2);
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

mkdirSync(outDir, { recursive: true });

const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
const page = list.find((t) => t.type === "page");
if (!page) throw new Error("no page target: " + JSON.stringify(list));

const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });

let msgId = 0;
const pending = new Map();
ws.onmessage = (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
};
function send(method, params = {}) {
  const id = ++msgId;
  return new Promise((res, rej) => {
    pending.set(id, (m) => (m.error ? rej(new Error(method + ": " + JSON.stringify(m.error))) : res(m.result)));
    ws.send(JSON.stringify({ id, method, params }));
  });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Click via selector so the scenes survive layout changes (coordinates broke
// whenever the dashboard chrome moved; see docs/demo.md).
async function click(selector) {
  const { result, exceptionDetails } = await send("Runtime.evaluate", {
    expression: `(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return "missing"; el.click(); return "ok"; })()`,
    returnByValue: true,
  });
  if (exceptionDetails || result.value !== "ok") throw new Error(`click ${selector}: ${result?.value ?? "eval failed"}`);
}

let frame = 0;
async function shot(label) {
  const { data } = await send("Page.captureScreenshot", { format: "png" });
  const name = `${String(frame++).padStart(2, "0")}-${label}.png`;
  writeFileSync(join(outDir, name), Buffer.from(data, "base64"));
  console.log("frame", name);
}

await send("Page.enable");
await send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
await send("Page.navigate", { url });
await sleep(2500); // let React mount and fetch

await shot("overview");                 // scene 1: timeline of the inject session
await click(".message-row:nth-of-type(6)"); await sleep(700);
await shot("message-detail");           // scene 2: tools/call payload in the detail panel
await click(".view-tab:nth-of-type(2)"); await sleep(700);
await shot("security-tab");             // scene 3: security events
await click(".view-tab:nth-of-type(3)"); await sleep(700);
await shot("context-tab");              // scene 4: context bloat analysis
await click(".view-tab:nth-of-type(4)"); await sleep(700);
await shot("inject-tab");               // scene 5: injected faults
await click(".view-tab:nth-of-type(1)"); await sleep(700);
await click(".session-row:nth-of-type(2)"); await sleep(900);
await shot("clean-session");            // scene 6: the clean session timeline
await click(".theme-toggle"); await sleep(700);
await shot("light-theme");              // scene 7: the same timeline in the light theme

ws.close();
console.log("done:", frame, "frames");
