// Records the console tour video against the live stack (1280x720). Includes a REAL attack sent over UDP 5514
// while recording: quiet banner -> attack -> alarm -> incident -> evidence. Usage: node tour.mjs <outDir>
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { BASE, REPO, creds, launch, sleep } from "./lib.mjs";

const out = process.argv[2];
const C = creds();
const TRAFFIC = path.join(REPO, "tools", "console_tour_traffic.py");
const ATTACKER = "203.0.113.99";

const browser = await launch();

// ---- pre-step (not recorded): close open high alarms so the banner starts quiet ----
{
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto(BASE + "/"); await page.waitForSelector("#u");
  await page.fill("#u", C.admin[0]); await page.fill("#p", C.admin[1]); await page.click("form button.btn.primary");
  await page.waitForSelector(".nav a[href=\"#/alarms\"]");
  const csrf = (await (await page.request.get(`${BASE}/api/auth/me`)).json()).csrf_token;
  const al = await (await page.request.get(`${BASE}/api/alerts?gte=0`)).json();
  let closed = 0;
  for (const h of al.hits?.hits || []) {
    const a = h._source;
    if (["high", "critical"].includes(String(a.level).toLowerCase()) && !["closed", "false_positive"].includes(a.triage?.status)) {
      const r = await page.request.post(`${BASE}/api/triage/alerts/${a.alert_id}/triage`, { data: { status: "closed", note: "lab alarm from an earlier run" }, headers: { "X-CSRF-Token": csrf } });
      if (r.ok()) closed++;
    }
  }
  console.log("pre-step: closed", closed, "earlier lab alarms");
  await ctx.close();
}

// ---- recorded tour ----
const W = 1280, H = 720;
const ctx = await browser.newContext({ viewport: { width: W, height: H }, locale: "en-GB", colorScheme: "light" });
await ctx.addInitScript(() => {
  // a visible pointer, since headless video records no cursor
  const add = () => {
    if (document.getElementById("__cur")) return;
    const d = document.createElement("div");
    d.id = "__cur";
    d.style.cssText = "position:fixed;left:-40px;top:-40px;width:22px;height:22px;border-radius:50%;border:2px solid #4f46e5;background:rgba(79,70,229,.18);z-index:2147483647;pointer-events:none;transition:transform .08s,background .08s;margin:-11px 0 0 -11px";
    document.documentElement.appendChild(d);
    addEventListener("mousemove", (e) => { d.style.left = e.clientX + "px"; d.style.top = e.clientY + "px"; }, true);
    addEventListener("mousedown", () => { d.style.transform = "scale(.7)"; d.style.background = "rgba(79,70,229,.5)"; }, true);
    addEventListener("mouseup", () => { d.style.transform = "scale(1)"; d.style.background = "rgba(79,70,229,.18)"; }, true);
  };
  if (document.documentElement) add(); else addEventListener("DOMContentLoaded", add);
  addEventListener("load", add);
});
const page = await ctx.newPage();
// frames via the browser's screencast (no extra binary): kept with their timestamps, encoded by the system ffmpeg at the end
const cdp = await ctx.newCDPSession(page);
const frames = [];
cdp.on("Page.screencastFrame", async ({ data, metadata, sessionId }) => {
  frames.push({ t: metadata.timestamp, data });
  await cdp.send("Page.screencastFrameAck", { sessionId }).catch(() => {});
});
await cdp.send("Page.startScreencast", { format: "jpeg", quality: 82, maxWidth: W, maxHeight: H, everyNthFrame: 1 });
let mx = 640, my = 360;
const glide = async (x, y, steps = 24) => { await page.mouse.move(x, y, { steps }); mx = x; my = y; };
const clickOn = async (loc, pause = 700) => {
  await loc.scrollIntoViewIfNeeded().catch(() => {});
  const bb = await loc.boundingBox();
  if (!bb) return false;
  await glide(bb.x + bb.width / 2, bb.y + bb.height / 2);
  await sleep(250); await page.mouse.down(); await page.mouse.up(); await sleep(pause);
  return true;
};
const typeInto = async (sel, text, delay = 70) => { const l = page.locator(sel); await clickOn(l, 200); await page.keyboard.type(text, { delay }); };
const go = async (r, ms = 1800) => { await page.goto(`${BASE}/#/${r}`); await sleep(ms); };
const nav = async (r, ms = 2200) => { await clickOn(page.locator(`.nav a[href="#/${r}"]`), ms); };

await page.goto(BASE + "/"); await page.waitForSelector("#u"); await sleep(2200);
await glide(900, 300, 30); await sleep(600);
await typeInto("#u", C.admin[0]);
await typeInto("#p", C.admin[1], 60);
await sleep(500);
await clickOn(page.locator("form button.btn.primary"), 400);
await page.waitForSelector(".nav a[href=\"#/alarms\"]", { timeout: 20000 });
await sleep(2800);                       // Overview, banner quiet

// ---- the attack: real UDP traffic into WS-1 while we watch the pipeline ----
await nav("operations", 1500);
const proc = spawn("python", [TRAFFIC, "127.0.0.1", "5514", ATTACKER], { stdio: "ignore" });
const t0 = Date.now();
while (Date.now() - t0 < 70000) {
  if (await page.$(".banner.active")) break;
  await glide(380 + Math.random() * 500, 300 + Math.random() * 200, 18);
  await sleep(1400);
}
await sleep(1500);
await nav("overview", 3200);             // banner active, mimic counters moved
await clickOn(page.locator(".banner .btn"), 2600);   // Open top alarm
await clickOn(page.locator("button.btn.primary", { hasText: /acknowledge/i }), 1800).catch(() => {});

await nav("incidents", 1800);
await clickOn(page.locator("table.data tbody tr.clk").first(), 2000);
await clickOn(page.locator("button.btn", { hasText: /build/i }).first(), 3200);

await nav("events", 1500);
await typeInto('input[type=search]', `ip:${ATTACKER} class:4002`, 55);
await sleep(1800);
await clickOn(page.locator("table.data tbody tr").first(), 1600);
await clickOn(page.locator("button", { hasText: /^OCSF$/ }).first(), 2600);

await nav("coverage", 3000);
await nav("sources", 1600);
await clickOn(page.locator("button", { hasText: /rsyslog/i }).first(), 3200);

await nav("inventory", 1800);
const mac = "DE:AD:BE:EF:20:02"; // fixed: re-recording updates this device instead of adding a duplicate
await typeInto('form[aria-label="Add device"] input[name=mac]', mac, 45);
await typeInto('form[aria-label="Add device"] input[name=hostname]', "plc-line-2", 45);
await typeInto('form[aria-label="Add device"] input[name=ip]', "10.20.0.14", 45);
await page.locator('form[aria-label="Add device"] select[name=sector]').selectOption("datacenter");
await clickOn(page.locator('form[aria-label="Add device"] button.btn.primary'), 2400);

await nav("operations", 2600);
await nav("settings", 2800);
await clickOn(page.locator('.top .seg button:has-text("DE")'), 2200);
await nav("overview", 1800);
await clickOn(page.locator(".top .icon-btn"), 3200);
await clickOn(page.locator('.top .seg button:has-text("EN")'), 1500);

await sleep(800);
await cdp.send("Page.stopScreencast").catch(() => {});
await ctx.close();
await browser.close();

// frames -> mp4 (variable frame rate: each frame is held until the next one arrives)
const dir = `${out}/frames`;
fs.rmSync(dir, { recursive: true, force: true });
fs.mkdirSync(dir, { recursive: true });
const lines = [];
frames.forEach((f, i) => {
  const name = `f${String(i).padStart(5, "0")}.jpg`;
  fs.writeFileSync(`${dir}/${name}`, Buffer.from(f.data, "base64"));
  const next = frames[i + 1]?.t ?? f.t + 1;
  lines.push(`file '${dir}/${name}'`, `duration ${Math.max(0.02, next - f.t).toFixed(3)}`);
});
lines.push(`file '${dir}/f${String(frames.length - 1).padStart(5, "0")}.jpg'`);
fs.writeFileSync(`${out}/frames.txt`, lines.join("\n"));
execFileSync("ffmpeg", ["-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", `${out}/frames.txt`,
  "-vf", "fps=25,scale=1280:720,format=yuv420p", "-c:v", "libx264", "-crf", "29", "-preset", "slow", "-movflags", "+faststart", "-an", `${out}/tour.mp4`]);
console.log("frames", frames.length, "->", `${out}/tour.mp4`, "attack process exit", proc.exitCode);
