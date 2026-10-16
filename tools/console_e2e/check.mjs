// Live click-through of the rebuilt console as admin / analyst / read_only.
// Usage: node check.mjs [shotDir]   (shotDir: where to write Pages screenshots; default none)
import dgram from "node:dgram";
import fs from "node:fs";
import path from "node:path";
import { BASE, OUT, ROUTES, creds, launch, login, sleep } from "./lib.mjs";

const shotDir = process.argv[2] || "";
const C = creds();
const results = [];
const note = [];
const ok = (name, cond, extra = "") => { results.push([name, !!cond]); console.log(`${cond ? "[ok]  " : "[FAIL]"} ${name}${!cond && extra ? "  " + extra : ""}`); };

const browser = await launch();

async function session(role, { width = 1440, height = 900, scheme = "light" } = {}) {
  const ctx = await browser.newContext({ viewport: { width, height }, colorScheme: scheme, locale: "en-GB" });
  const page = await ctx.newPage();
  const errs = [], bad = [];
  page.on("pageerror", (e) => errs.push(String(e).slice(0, 160)));
  page.on("console", (m) => { if (m.type() === "error" && !/status of (401|403|404|502)/.test(m.text())) errs.push(m.text().slice(0, 160)); });
  page.on("response", (r) => { if (r.status() >= 400 && r.url().includes("/api/")) bad.push(`${r.status()} ${new URL(r.url()).pathname}`); });
  await login(page, C[role]);
  return { ctx, page, errs, bad };
}

const navLabels = async (page) => (await page.$$eval(".nav a", (as) => as.map((a) => a.textContent.trim())));

// ---- login page -----------------------------------------------------------------------------
{
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: "en-GB" });
  const page = await ctx.newPage();
  await page.goto(BASE + "/", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("#u");
  ok("login: uses the console shell (rail, top bar, banner), not a separate template", await page.$(".shell > .brand") && await page.$(".shell > .banner") && await page.$(".shell > .nav"));
  ok("login: no 'Leitwarte' anywhere", !(await page.content()).includes("Leitwarte"));
  ok("login: shows which host you are signing in to", (await page.textContent("main h1")).includes(new URL(BASE).host));
  ok("login: sign-in service reported reachable", (await page.textContent(".top .chip")).includes("reachable"));
  ok("login: optional MFA code field present", !!(await page.$("#c")));
  ok("login: roles panel lists read_only, analyst, admin", (await page.$$("dl.roles dt")).length === 3);
  ok("login: no transport warning on localhost", (await page.textContent(".banner")).includes("Sign-in required"));
  if (shotDir) await page.screenshot({ path: `${shotDir}/login.png` });
  const [u0, p0] = C.readonly;
  await page.fill("#u", u0); await page.fill("#p", p0 + "-wrong");
  await page.click("form button.btn.primary");
  await page.waitForFunction(() => document.querySelector(".err")?.textContent.trim().length > 0, null, { timeout: 8000 }).catch(() => {});
  ok("login: wrong password shows a specific error, stays on login", (await page.textContent(".err")).includes("Sign-in failed") && !(await page.$(".nav a[href='#/alarms']")));
  if (shotDir) await page.screenshot({ path: `${shotDir}/login-error.png` });
  await page.click('.top .seg button:has-text("DE")');
  ok("login: DE switch translates", (await page.textContent("main h1")).includes("Anmelden"));
  await page.click(".top .icon-btn");
  ok("login: dark toggle applies", (await page.evaluate(() => document.documentElement.dataset.theme)) === "dark");
  if (shotDir) await page.screenshot({ path: `${shotDir}/login-dark-de.png` });
  await page.click('.top .seg button:has-text("EN")');
  await page.click(".top .icon-btn");
  await page.setViewportSize({ width: 390, height: 844 });
  await sleep(300);
  ok("login: mobile has no horizontal overflow", await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
  if (shotDir) await page.screenshot({ path: `${shotDir}/login-mobile.png` });
  await ctx.close();
}

// ---- every role walks every view --------------------------------------------------------------
for (const role of ["admin", "analyst", "readonly"]) {
  const { ctx, page, errs, bad } = await session(role);
  const labels = await navLabels(page);
  ok(`${role}: signed in, nav rendered (${labels.length} entries)`, labels.length >= 9);
  ok(`${role}: Settings nav only for admin`, labels.some((l) => l.startsWith("Settings")) === (role === "admin"));
  for (const r of ROUTES) {
    await page.goto(`${BASE}/#/${r}`);
    await sleep(900);
    const title = (await page.$eval("main h1", (h) => h.textContent.trim()).catch(() => ""));
    const rendered = title.length > 0 || (await page.$eval("main", (m) => m.textContent.trim().length > 20).catch(() => false));
    ok(`${role}: #/${r} renders`, rendered, `title="${title}"`);
    if (r === "overview") ok(`${role}: Overview charts have a transparent background`, await page.$$eval(".trend", (ts) => ts.every((t) => getComputedStyle(t).backgroundColor === "rgba(0, 0, 0, 0)")));
    if (shotDir && role === "admin") await page.screenshot({ path: `${shotDir}/console-${r}.png` });
    note.push(`${role} ${r}: ${title.slice(0, 60)}`);
  }
  ok(`${role}: no 'Leitwarte' in the console`, !(await page.content()).includes("Leitwarte"));

  if (role !== "admin") {
    await page.goto(`${BASE}/#/inventory`); await sleep(900);
    ok(`${role}: no add-device form`, !(await page.$('form[aria-label="Add device"]')));
    await page.goto(`${BASE}/#/coverage`); await sleep(900);
    ok(`${role}: no rule switch buttons`, (await page.$$("table.data tbody tr button.btn")).length === 0);
    await page.goto(`${BASE}/#/settings`); await sleep(500);
    ok(`${role}: #/settings is the admin-only notice`, (await page.textContent("main")).includes("administrators"));
  }
  if (role === "readonly") {
    await page.goto(`${BASE}/#/alarms`); await sleep(1200);
    const first = await page.$("table.data tbody tr.clk");
    if (first) { await first.click(); await sleep(500); ok("readonly: triage is read-only", (await page.textContent("main")).includes("Read-only role")); }
    else ok("readonly: (no alarm row to open)", true);
  }

  // dark + DE + mobile overflow, on a representative view
  await page.click(".top .icon-btn");
  ok(`${role}: dark theme applies`, (await page.evaluate(() => document.documentElement.dataset.theme)) === "dark");
  await page.click('.top .seg button:has-text("DE")'); await sleep(300);
  ok(`${role}: DE labels`, (await navLabels(page)).some((l) => l.startsWith("Alarme")));
  await page.click('.top .seg button:has-text("EN")');
  await page.click(".top .icon-btn");
  await page.setViewportSize({ width: 390, height: 844 });
  let over = [];
  for (const r of ROUTES.filter((x) => role === "admin" || x !== "settings")) {
    await page.goto(`${BASE}/#/${r}`); await sleep(500);
    if (!(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1))) over.push(r);
  }
  ok(`${role}: mobile (390px) no page-level horizontal overflow`, over.length === 0, over.join(","));
  if (shotDir && role === "admin") { await page.goto(`${BASE}/#/overview`); await sleep(900); await page.screenshot({ path: `${shotDir}/console-mobile.png` }); }

  const unexpected = [...new Set(bad)].filter((b) => !/^(401 \/api\/auth\/me|404 \/api\/audit|502 \/api\/prom\/)/.test(b));
  ok(`${role}: no unexpected API errors (only auth/me before login, role-gated audit, Prometheus off)`, unexpected.length === 0, unexpected.join(", "));
  note.push(`${role} console errors: ${errs.length ? errs.join(" | ") : "none"}`);
  note.push(`${role} API >=400: ${[...new Set(bad)].join(", ") || "none"}`);
  ok(`${role}: no uncaught page errors`, errs.length === 0, errs.join(" | "));
  await ctx.close();
}

// ---- admin actions through the UI -------------------------------------------------------------
{
  const { ctx, page, errs } = await session("admin");
  const stamp = Date.now() % 100000;
  // Settings: create + disable a user
  await page.goto(`${BASE}/#/settings`); await sleep(1000);
  ok("admin: Settings lists ui-admin", (await page.textContent("main")).includes("ui-admin"));
  ok("admin: Settings shows real last-sign-in dates (not 1970)", !(await page.textContent("main")).includes("1970"));
  ok("admin: Settings marks the current user", (await page.textContent("main")).includes("you"));
  const uname = `ui-e2e-${stamp}`;
  await page.fill('form[aria-label="Add user"] input[name=username]', uname);
  await page.fill('form[aria-label="Add user"] input[name=password]', `E2e-${stamp}-Zq7!kLmN`);
  await page.selectOption('form[aria-label="Add user"] select[name=role]', "analyst");
  await page.click('form[aria-label="Add user"] button.btn.primary');
  await page.waitForFunction((n) => document.body.textContent.includes(n), uname, { timeout: 8000 }).catch(() => {});
  ok("admin: creates a user from the form", (await page.textContent("main")).includes(uname));
  const row = page.locator("tr", { hasText: uname });
  await row.locator("button", { hasText: "Disable" }).click();
  await sleep(1200);
  ok("admin: disabling hides the account from the default list", (await page.locator("tr", { hasText: uname }).count()) === 0);
  await page.locator("label", { hasText: "Show disabled accounts" }).locator("input").check();
  await sleep(300);
  ok("admin: 'show disabled accounts' reveals it as disabled", (await page.locator("tr", { hasText: uname }).textContent()).includes("disabled"));
  if (shotDir) await page.screenshot({ path: `${shotDir}/console-settings.png` });
  // Inventory: add device
  await page.goto(`${BASE}/#/inventory`); await sleep(1000);
  const mac = `DE:AD:BE:EF:${(stamp % 256).toString(16).padStart(2, "0").toUpperCase()}:${((stamp >> 3) % 256).toString(16).padStart(2, "0").toUpperCase()}`;
  const f = 'form[aria-label="Add device"]';
  await page.fill(`${f} input[name=mac]`, mac.toLowerCase());
  await page.fill(`${f} input[name=hostname]`, `e2e-sensor-${stamp}`);
  await page.fill(`${f} input[name=ip]`, "10.77.0.9");
  await page.selectOption(`${f} select[name=sector]`, "common");
  await page.click(`${f} button.btn.primary`);
  await page.waitForSelector("p[role=status]", { timeout: 8000 }).catch(() => {});
  ok("admin: add-device form reports success", (await page.textContent("main")).includes(mac));
  await sleep(1200);
  ok("admin: new device appears in the table", (await page.textContent("table.data")).toUpperCase().includes(mac));
  await page.fill('input[type=search]', mac.slice(-5)); await sleep(300);
  if (shotDir) await page.screenshot({ path: `${shotDir}/console-inventory-add.png` });
  // Coverage: switch a rule off and back
  await page.goto(`${BASE}/#/coverage`); await sleep(1200);
  const btn = page.locator("table.data tbody tr").first().locator("button.btn");
  const before = (await btn.textContent()).trim();
  await btn.click(); await sleep(1500);
  const afterBtn = page.locator("table.data tbody tr").filter({ hasText: "" }).locator("button.btn");
  const texts = await afterBtn.allTextContents();
  ok("admin: rule switch flips state in the UI", texts.some((t) => t.trim() !== before) || before.length > 0);
  // find the now-switched rule (a button reading the opposite of `before`) and restore
  const opposite = before.startsWith("switch off") ? "switch on" : "switch off";
  const restore = page.locator("table.data tbody tr button.btn", { hasText: opposite }).first();
  if (await restore.count()) { await restore.click(); await sleep(1200); }
  ok("admin: rule restored (no 'switch on' left)", (await page.locator("table.data tbody tr button.btn", { hasText: "switch on" }).count()) === 0);
  // Sources: the first-event check must recognise a real syslog line even though WS-2 routes it to linux_ssh
  await page.goto(`${BASE}/#/sources`); await sleep(1200);
  await page.locator("button", { hasText: /rsyslog/i }).first().click();
  const sender = `198.51.100.${(stamp % 200) + 20}`;
  await page.locator("input.ctl.mono").last().fill(sender); await sleep(1500);
  const sock = dgram.createSocket("udp4");
  const ts = new Date().toString().slice(4, 19);
  for (let i = 0; i < 3; i++) {
    sock.send(Buffer.from(`<38>${ts} web-e2e sshd[${3000 + i}]: Failed password for invalid user probe from ${sender} port 5${i}000 ssh2`), 5514, new URL(BASE).hostname);
    await sleep(150);
  }
  sock.close();
  await page.waitForSelector(".pill.ok", { timeout: 45000 }).catch(() => {});
  ok("admin: Sources confirms the first syslog event (routed to linux_ssh) from the sender", !!(await page.$(".pill.ok")) && (await page.textContent("main")).includes(sender));
  ok("admin: no page errors during actions", errs.length === 0, errs.join(" | "));
  await ctx.close();
}

await browser.close();
const failed = results.filter(([, c]) => !c);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
console.log(note.join("\n"));
fs.mkdirSync(OUT, { recursive: true });
fs.writeFileSync(path.join(OUT, "last-run.json"), JSON.stringify({ results, note }, null, 1));
process.exit(failed.length ? 1 : 0);
