// Chapter: sign-in to settings. The sign-in page, what an analyst can and cannot do, then an admin adds a user,
// changes a role, adds a device, switches a rule off and on, and finds each action in the audit trail.
//   (remove a previous 'night-shift' user first: node's lab cleanup, or the stack's rbac.sqlite)   node chapter_access.mjs <outDir>
import { record } from "./tourlib.mjs";

const out = process.argv[2];
const stamp = String(Date.now() % 10000);
await record("chapter-access", out, async ({ page, sleep, clickOn, typeInto, nav, signIn, signOut }) => {
  // the door: host, reachability, MFA field, roles; language and theme
  await page.goto((await import("./lib.mjs")).BASE + "/"); await page.waitForSelector("#u"); await sleep(3200);
  await clickOn(page.locator('.top .seg button:has-text("DE")'), 1800);
  await clickOn(page.locator('.top .seg button:has-text("EN")'), 900);
  await clickOn(page.locator(".top .icon-btn"), 1500);
  await clickOn(page.locator(".top .icon-btn"), 1000);

  // an analyst: no Settings entry, no add-device form, no rule switches
  await signIn("analyst", { look: 200 });
  await nav("inventory", 2200);
  await nav("coverage", 2200);
  await clickOn(page.locator("a.chip.user"), 2400);       // account: MFA enrolment lives here
  await signOut();

  // an admin: Settings appears
  await signIn("admin", { look: 400 });
  await nav("settings", 2400);
  const f = 'form[aria-label="Add user"]';
  await typeInto(`${f} input[name=username]`, "night-shift", 55);
  await typeInto(`${f} input[name=password]`, `Shift-${stamp}-Kq7!zRtW`, 40);
  await page.locator(`${f} select[name=role]`).selectOption("read_only");
  await sleep(500);
  await clickOn(page.locator(`${f} button.btn.primary`), 2200);
  await page.locator('select[aria-label="Role night-shift"]').selectOption("analyst");   // promoted
  await sleep(2200);
  await clickOn(page.locator("tr", { hasText: "night-shift" }).locator("button", { hasText: "Disable" }), 2000);
  await clickOn(page.locator("label", { hasText: "Show disabled accounts" }).locator("input"), 2200);

  await nav("inventory", 1800);
  const d = 'form[aria-label="Add device"]';
  await typeInto(`${d} input[name=mac]`, "DE:AD:BE:EF:20:07", 45);
  await typeInto(`${d} input[name=hostname]`, "fw-dmz-02", 45);
  await typeInto(`${d} input[name=ip]`, "10.20.0.2", 45);
  await page.locator(`${d} select[name=sector]`).selectOption("common");
  await typeInto(`${d} input[name=type]`, "firewall", 45);
  await clickOn(page.locator(`${d} button.btn.primary`), 2600);

  await nav("coverage", 2000);
  const sw = page.locator("table.data tbody tr").first().locator("button.btn");
  await clickOn(sw, 2200);                                  // switch off: detection honours it within seconds
  await nav("audit", 3600);                                 // rule_toggle, user_create, user_update, inventory_asset_upsert
  await nav("coverage", 1400);
  await clickOn(page.locator("table.data tbody tr button.btn", { hasText: "switch on" }).first(), 2200);  // and back on
  await nav("overview", 1200);
}, { posterAt: 60 });
