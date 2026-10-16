// Checks the static demo build (docs/demo) from a local static server, no backend needed.
//   python -m http.server 8099 --directory docs      (in another shell)
//   node demo.mjs [shotDir]
import { launch, sleep } from "./lib.mjs";

const URL = process.env.FENGARDE_DEMO_URL || "http://127.0.0.1:8099/demo/";
const shotDir = process.argv[2] || "";
const res = [];
const ok = (n, c, x = "") => { res.push(c); console.log(`${c ? "[ok]  " : "[FAIL]"} ${n}${!c && x ? "  " + x : ""}`); };

const b = await launch();
const ctx = await b.newContext({ viewport: { width: 1440, height: 900 }, locale: "en-GB" });
const page = await ctx.newPage();
const errs = [], bad = [];
page.on("pageerror", (e) => errs.push(String(e).slice(0, 140)));
page.on("console", (m) => { if (m.type() === "error") errs.push(m.text().slice(0, 140)); });
page.on("response", (r) => { if (r.status() >= 400) bad.push(`${r.status()} ${r.url().slice(-60)}`); });
const shot = (n) => shotDir ? page.screenshot({ path: `${shotDir}/${n}.png` }) : null;

await page.goto(URL, { waitUntil: "load" });
await page.waitForSelector('.nav a[href="#/alarms"]', { timeout: 15000 });
await sleep(1500);
ok("demo: console renders with no sign-in", !!(await page.$(".shell .nav")) && !(await page.$("#u")));
ok("demo: badged as recorded lab data", (await page.textContent(".chip.demo")).toLowerCase().includes("recorded"));
ok("demo: starts quiet (no active alarms)", (await page.textContent(".banner")).toLowerCase().includes("no active alarms"));
ok("demo: no sign-out or classic link", !(await page.$("text=Sign out")) && !(await page.$("a.classic")));
await shot("demo-idle");

// replay the attack
const t0 = Date.now();
await page.click("button:has-text('Replay the attack')");
await sleep(700);
ok("replay: button shows progress and disables", (await page.textContent(".demo-bar")).includes("Replaying"));
await page.waitForSelector(".banner.active", { timeout: 20000 });
const tAlarm = Date.now() - t0;
ok(`replay: banner turns active after the alarms arrive (${(tAlarm / 1000).toFixed(1)} s)`, tAlarm > 1500 && tAlarm < 15000, String(tAlarm));
await page.waitForFunction(() => /Incidents\s*\d/.test(document.querySelector(".nav")?.textContent || "") || document.querySelector('.nav a[href="#/incidents"] .count'), null, { timeout: 20000 });
await sleep(800);
ok("replay: the incident appears in the nav", !!(await page.$('.nav a[href="#/incidents"] .count')));
await page.goto(URL + "#/incidents"); await sleep(1200);
await page.locator("table.data tbody tr.clk").first().click(); await sleep(900);
ok("incident detail shows the causal graph", !!(await page.$(".graph")));
await page.locator("button.btn", { hasText: /build/i }).first().click(); await sleep(1500);
ok("evidence package builds and reads Verified", (await page.textContent("main")).includes("Verified"));
await shot("demo-incident");

// alarm faceplate, triage and a recorded NIS2 report
await page.goto(URL + "#/alarms"); await sleep(1200);
await page.locator("table.data tbody tr.clk").first().click(); await sleep(900);
await page.locator("button.btn.primary", { hasText: /acknowledge/i }).click(); await sleep(900);
ok("triage: acknowledge changes the status locally", (await page.textContent("main")).toLowerCase().includes("triaged"));
await page.locator("button.btn", { hasText: /NIS2/ }).click(); await sleep(900);
ok("NIS2 draft report comes from the recording", (await page.textContent(".report")).length > 200);
await shot("demo-alarm");

// admin writes are local only
await page.goto(URL + "#/inventory"); await sleep(1000);
const f = 'form[aria-label="Add device"]';
await page.fill(`${f} input[name=mac]`, "DE:AD:BE:EF:77:01"); await page.fill(`${f} input[name=hostname]`, "demo-plc");
await page.selectOption(`${f} select[name=sector]`, "datacenter"); await page.click(`${f} button.btn.primary`); await sleep(1200);
ok("add device works locally", (await page.textContent("table.data")).includes("demo-plc"));
await page.goto(URL + "#/settings"); await sleep(900);
ok("Settings lists recorded users", (await page.textContent("main")).includes("ui-admin"));
await page.goto(URL + "#/operations"); await sleep(1500);
ok("Operations says Prometheus is not part of the demo", (await page.textContent("main")).toLowerCase().includes("not reachable") || (await page.textContent("main")).toLowerCase().includes("prometheus"));
await page.goto(URL + "#/events"); await sleep(900);
ok("Events log explorer has rows", (await page.$$("table.data tbody tr")).length > 5);

// reset hides the attack again
await page.click("button:has-text('Reset')"); await sleep(1500);
ok("reset: quiet again", (await page.textContent(".banner")).toLowerCase().includes("no active alarms"));

// German
await page.click('.top .seg button:has-text("DE")'); await sleep(500);
ok("DE: demo bar and nav translate", (await page.textContent(".demo-bar")).includes("Angriff") && (await page.textContent(".nav")).includes("Alarme"));

await page.setViewportSize({ width: 390, height: 844 });
for (const r of ["overview", "alarms", "incidents", "events", "coverage", "sources", "inventory", "operations", "audit", "settings"]) {
  await page.goto(URL + "#/" + r); await sleep(500);
  if (!(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1))) { ok(`mobile: #/${r} no horizontal overflow`, false); }
}
ok("demo: no uncaught errors and no failed requests", errs.length === 0 && bad.length === 0, errs.concat(bad).join(" | "));
await b.close();
const failed = res.filter((r) => !r).length;
console.log(`${res.length - failed}/${res.length} passed`);
process.exit(failed ? 1 : 0);
