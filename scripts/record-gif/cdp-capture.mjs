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

async function click(x, y) {
  await send("Input.dispatchMouseEvent", { type: "mouseMoved", x, y });
  await send("Input.dispatchMouseEvent", { type: "mousePressed", x, y, button: "left", clickCount: 1 });
  await send("Input.dispatchMouseEvent", { type: "mouseReleased", x, y, button: "left", clickCount: 1 });
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
await click(600, 332); await sleep(700);
await shot("message-detail");           // scene 2: tools/call payload in the detail panel
await click(385, 75); await sleep(700);
await shot("security-tab");             // scene 3: security events
await click(455, 75); await sleep(700);
await shot("context-tab");              // scene 4: context bloat analysis
await click(520, 75); await sleep(700);
await shot("inject-tab");               // scene 5: injected faults
await click(310, 75); await sleep(700);
await click(130, 120); await sleep(900);
await shot("clean-session");            // scene 6: the clean session timeline

ws.close();
console.log("done:", frame, "frames");
