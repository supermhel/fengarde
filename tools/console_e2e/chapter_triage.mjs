// Chapter: an analyst works an alarm. Note and verdict, the NIS2 early-warning draft in German, the incident report,
// and the log explorer (facets, keyboard, raw versus OCSF).      node chapter_triage.mjs <outDir>
import { record } from "./tourlib.mjs";

const out = process.argv[2];
await record("chapter-triage", out, async ({ page, sleep, clickOn, typeInto, nav, signIn }) => {
  await signIn("analyst", { look: 300, fast: true });
  await nav("alarms", 2200);
  await clickOn(page.locator("table.data tbody tr.clk").first(), 2400);
  await typeInto("textarea.note-in", "Source is the lab traffic script. Brute force confirmed in the raw lines.", 38);
  await sleep(700);
  await clickOn(page.locator("button.btn", { hasText: /true positive/i }), 2200);
  await clickOn(page.locator(".seg button", { hasText: /^OCSF$/ }).first(), 1800);     // the events that fired it, normalized
  await clickOn(page.locator(".seg button", { hasText: /^Raw$/ }).first(), 1200);
  // NIS2 early warning, in German
  await page.locator('select[aria-label="NIS2 stage"]').selectOption("early_warning"); await sleep(600);
  await page.locator('select[aria-label="NIS2 language"]').selectOption("de"); await sleep(600);
  await clickOn(page.locator("button.btn", { hasText: /NIS2/ }).last(), 3600);
  await page.locator(".report").scrollIntoViewIfNeeded(); await sleep(2600);

  await nav("incidents", 2000);
  await clickOn(page.locator("table.data tbody tr.clk").first(), 2200);
  await clickOn(page.locator("button.btn", { hasText: /build/i }).first(), 2600);
  await page.locator('select[aria-label*="eport"], select.ctl').last().selectOption("de").catch(() => {});
  await clickOn(page.locator("button.btn", { hasText: /^Report$/ }).last(), 3400);

  await nav("events", 1800);
  await clickOn(page.locator("button.row").first(), 2200);                              // a facet becomes a query token
  await typeInto('input[type=search]', " status:Failure", 60);
  await sleep(1800);
  await page.keyboard.press("Escape");
  await clickOn(page.locator("table.data tbody tr").first(), 1400);
  await page.keyboard.press("j"); await sleep(700); await page.keyboard.press("j"); await sleep(1300);
  await clickOn(page.locator(".seg button", { hasText: /^OCSF$/ }).first(), 2600);
  await nav("coverage", 3000);
}, { posterAt: 24 });
