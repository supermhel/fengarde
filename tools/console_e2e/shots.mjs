// Deliberate screenshot states of the live console for the Pages tour.  Usage: node shots.mjs <outDir>
import { BASE, creds, launch, login, sleep } from "./lib.mjs";

const out = process.argv[2];
const C = creds();
const b = await launch();
const ctx = await b.newContext({ viewport: { width: 1440, height: 900 }, locale: "en-GB", colorScheme: "light" });
const page = await ctx.newPage();
await login(page, C.admin);
const go = async (r, ms = 1600) => { await page.goto(`${BASE}/#/${r}`); await sleep(ms); };
const shot = async (n) => { await page.screenshot({ path: `${out}/${n}.png` }); console.log("shot", n); };

await go("overview", 2200); await shot("console-overview");

await go("alarms", 1500);
const a0 = page.locator("table.data tbody tr.clk").first();
if (await a0.count()) { await a0.click(); await sleep(1500); }
await shot("console-alarms");

await go("incidents", 1500);
const i0 = page.locator("table.data tbody tr.clk").first();
if (await i0.count()) { await i0.click(); await sleep(1500); }
const evBtn = page.locator("button.btn", { hasText: /build|evidence|nachweis/i }).first();
if (await evBtn.count()) { await evBtn.click(); await sleep(2000); }
await shot("console-incidents");

await go("events", 1500);
await page.fill('input[type=search]', "ip:203.0.113.77 class:4002");
await sleep(1200);
const e0 = page.locator("table.data tbody tr").first();
if (await e0.count()) { await e0.click(); await sleep(1000); }
await shot("console-events");

await go("coverage", 1600); await shot("console-coverage");

await go("sources", 1600);
await shot("console-sources");

await go("inventory", 1500);
const v0 = page.locator("table.data tbody tr.clk").first();
if (await v0.count()) { await v0.click(); await sleep(1500); }
await shot("console-inventory");

await go("operations", 2000); await shot("console-operations");
await go("audit", 1500); await shot("console-audit");
await go("settings", 1500); await shot("console-settings");

await go("overview", 1500);
await page.click(".top .icon-btn"); await sleep(500);
await shot("console-overview-dark");
await page.click(".top .icon-btn");

await page.setViewportSize({ width: 390, height: 844 });
await go("overview", 1500); await shot("console-mobile");
await b.close();
