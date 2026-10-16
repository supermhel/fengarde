// Operations view with Prometheus running: the panel must show real targets and numbers, not the unreachable note.
// Needs: docker compose -f infra/docker-compose.yml --profile observability up -d --no-deps prometheus  (wait ~30 s for scrapes)
// Usage: node prom.mjs [screenshotPath]
import { creds, launch, login, sleep, BASE } from "./lib.mjs";

const shot = process.argv[2] || "";
const C = creds();
const browser = await launch();
const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 }, locale: "en-GB" });
const page = await ctx.newPage();
const promCalls = [];
page.on("response", (r) => { if (r.url().includes("/api/prom/")) promCalls.push(`${r.status()} ${new URL(r.url()).pathname}`); });
await login(page, C.admin);
await page.goto(`${BASE}/#/operations`); await sleep(4000);
const text = await page.textContent("main");
const results = [];
const ok = (n, c, x = "") => { results.push(!!c); console.log(`${c ? "[ok]  " : "[FAIL]"} ${n}${!c && x ? "  " + x : ""}`); };
ok("Prometheus API answered 200 (targets and queries)", promCalls.length >= 2 && promCalls.every((c) => c.startsWith("200")), promCalls.join(", "));
ok("panel no longer says Prometheus is unreachable", !/not reachable|unreachable/i.test(text));
const rows = await page.$$eval("tr", (trs) => trs.map((t) => t.textContent || "").filter((t) => /ws\d-[a-z]+:\d+/.test(t)));
ok("panel lists the seven scrape targets, all up", rows.length === 7 && rows.every((r) => /up/.test(r) && !/down/i.test(r)), `${rows.length} rows`);
if (shot) await page.screenshot({ path: shot, fullPage: true });
await browser.close();
console.log(`${results.filter(Boolean).length}/${results.length} passed`);
process.exit(results.every(Boolean) ? 0 : 1);
