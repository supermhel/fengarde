// Checks the GitHub Pages site (docs/index.html) from a local static server, including the embedded demo console.
//   python -m http.server 8099 --directory docs      (in another shell)
//   node pages.mjs [shotDir]
import { launch, sleep } from "./lib.mjs";

const URL = process.env.FENGARDE_PAGES_URL || "http://127.0.0.1:8099/";
const shotDir = process.argv[2] || "";
const res = [];
const ok = (n, c, x = "") => { res.push(c); console.log(`${c ? "[ok]  " : "[FAIL]"} ${n}${!c && x ? "  " + x : ""}`); };
const b = await launch();

for (const [name, w, h] of [["desktop", 1440, 900], ["mobile", 390, 844]]) {
  const ctx = await b.newContext({ viewport: { width: w, height: h }, locale: "en-GB" });
  const page = await ctx.newPage();
  const errs = [], external = [];
  page.on("pageerror", (e) => errs.push(String(e).slice(0, 140)));
  page.on("console", (m) => { if (m.type() === "error") errs.push(m.text().slice(0, 140)); });
  page.on("request", (r) => { if (!r.url().startsWith(URL.replace(/\/$/, "")) && !r.url().startsWith("data:")) external.push(r.url().slice(0, 80)); });
  await page.goto(URL, { waitUntil: "load" });
  await sleep(1200);
  const shot = (n) => shotDir ? page.screenshot({ path: `${shotDir}/page-${name}-${n}.png` }) : null;

  ok(`${name}: makes no third-party requests`, external.length === 0, external.join(" | "));
  ok(`${name}: headline states the offer`, (await page.textContent("h1")).toLowerCase().includes("evidence out"));
  ok(`${name}: idle board lists the five stages as ready and claims nothing is running`, (await page.$$("#boardBody tr")).length === 5 && (await page.$$("#boardBody .st.idle")).length === 5 && (await page.$$("#boardBody .st.ok")).length === 0);
  ok(`${name}: no kickers above headings, no glyph icons`, (await page.$$(".sec-head > .tiny")).length === 0 && !/[▶↗]/.test(await page.textContent("body")));
  if (name === "desktop") ok("desktop: the first viewport shows at least four board rows", await page.evaluate(() => { const r = document.querySelectorAll("#boardBody tr")[3]; return !!r && r.getBoundingClientRect().bottom <= window.innerHeight; }));
  ok(`${name}: ticker can be paused`, await page.evaluate(() => { const b = document.querySelector("#tickerPause"); b.click(); const on = b.getAttribute("aria-pressed") === "true" && document.querySelector(".ticker").classList.contains("paused"); b.click(); return on; }));
  ok(`${name}: capability board has the honest rows (4 cancelled, 1 replacement)`, (await page.$$("#capBody .st.cancel")).length === 4 && (await page.$$("#capBody .st.replace")).length === 1);
  ok(`${name}: twelve view tiles link into the demo`, (await page.$$("#viewGrid a.view")).length === 12 && (await page.$$eval("#viewGrid a.view", (a) => a.filter((x) => x.getAttribute("href").includes("demo/")).length)) >= 11);
  ok(`${name}: no horizontal overflow`, await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1));
  ok(`${name}: the top bar fits the viewport (language toggle not clipped)`, await page.evaluate(() => document.querySelector(".top .seg").getBoundingClientRect().right <= window.innerWidth - 8));
  ok(`${name}: the ticker carries the numbers`, (await page.$$("#ticker .it")).length >= 10);
  ok(`${name}: seven reasons, each with a receipt`, (await page.$$("#whyList .why-row")).length === 7 && (await page.$$("#whyList .rcpt")).length === 7);
  ok(`${name}: all 46 rules are listed (7 OT, 5 AI agent)`, (await page.$$("#detBody .rl")).length === 46 && (await page.textContent("#detBody")).includes("Modbus"));
  ok(`${name}: GitHub is linked from nav, hero, closing and footer`, (await page.$$('a[href^="https://github.com/supermhel/fengarde"]')).length >= 8);
  ok(`${name}: nine architecture boxes, each linking to its directory`, (await page.$$eval("#archSvg a.an", (a) => a.filter((x) => /tree\/main\/services\/ws\d-/.test(x.getAttribute("href"))).length)) === 9);
  await shot("top");

  // replay the attack: board and embedded console move together
  await page.click("#replay");
  await page.waitForSelector("#boardBody tr.alarm-row", { timeout: 25000 });
  ok(`${name}: replay raises amber alarm rows on the board`, (await page.$$("#boardBody tr.alarm-row .st.check")).length >= 1);
  ok(`${name}: stages turn on time only once the replay has passed through them`, (await page.$$("#boardBody .st.ok")).length >= 1);
  ok(`${name}: the architecture boxes light as the attack passes`, (await page.$$("#archSvg .an.lit")).length >= 1 || (await page.waitForSelector("#archSvg .an.lit", { timeout: 6000 }).then(() => true).catch(() => false)));
  await page.waitForFunction(() => document.querySelectorAll("#boardBody tr").length >= 7 || /incident/i.test(document.querySelector("#boardBody")?.textContent || ""), null, { timeout: 25000 });
  ok(`${name}: the incident is announced`, /incident/i.test(await page.textContent("#boardBody")));
  await page.waitForFunction(() => /finished/i.test(document.querySelector("#boardState")?.textContent || ""), null, { timeout: 25000 });
  ok(`${name}: state reads finished and the button offers replay again`, (await page.textContent("#replayLabel")).toLowerCase().includes("again"));
  // verify the evidence inside the embedded console -> the board's incident row flips to verified
  const f = page.frameLocator("#frame");
  await f.locator('.nav a[href="#/incidents"]').click();
  await f.locator("table.data tbody tr.clk").first().click();
  await f.locator("button.btn", { hasText: /build/i }).first().click();
  await page.waitForSelector("#boardBody .st.verified", { timeout: 15000 }).catch(() => {});
  ok(`${name}: verifying evidence in the console flips the board row to verified`, !!(await page.$("#boardBody .st.verified")));
  await page.locator("#console").scrollIntoViewIfNeeded(); await sleep(500);
  await shot("replayed");
  await page.evaluate(() => window.scrollTo(0, 0)); await sleep(300);
  await shot("board");

  // German
  await page.click('[data-lang="de"]'); await sleep(500);
  ok(`${name}: DE translates headline, board and statuses`, (await page.textContent("h1")).includes("Belege raus") && (await page.textContent(".board-head h2")).includes("Abfahrt") && /geprüft|prüfen/.test(await page.textContent("#boardBody")));
  ok(`${name}: DE capability board says fällt aus`, (await page.textContent("#capBody")).includes("fällt aus"));
  await shot("de");
  await page.click('[data-lang="en"]');

  // second replay: the generated AI-to-OT chain (synthetic input, real pipeline code), started from the page's own button
  ok(`${name}: two replay buttons, the AI-to-OT one is labelled`, (await page.textContent("#replayAiLabel")).includes("AI-to-OT") && !(await page.$("#replayAi:disabled")));
  await page.evaluate(() => { window.__msgs = []; window.addEventListener("message", (e) => { if (e.data && e.data.source === "fengarde-demo") window.__msgs.push(e.data); }); });
  await page.click("#replayAi");
  await page.waitForFunction(() => /finished/i.test(document.querySelector("#boardState")?.textContent || "") && window.__msgs.some((m) => m.type === "replay-done"), null, { timeout: 90000 });
  const msgs = await page.evaluate(() => window.__msgs);
  const rules = msgs.filter((m) => m.type === "alarm").map((m) => m.rule);
  const incs = msgs.filter((m) => m.type === "incident");
  ok(`${name}: AI-to-OT replay raises 7 alarms with the chain's titles`, rules.length === 7 && ["n8n new webhook exposed", "outside business hours", "prompt-injection indicator", "non-allowlisted domain", "credential material", "Modbus/TCP write"].every((x) => rules.some((r) => r.includes(x))), rules.join(" | "));
  ok(`${name}: AI-to-OT replay announces two incidents (7 and 5 alarms)`, incs.length === 2 && incs.map((i) => i.alerts).sort().join() === "5,7", JSON.stringify(incs.map((i) => [i.entity, i.alerts])));
  ok(`${name}: board and terminal say synthetic input, not recorded`, /synthetic/i.test(await page.textContent("#boardTag")) && /synthetic/i.test(await page.textContent("#termSub")) && !/recorded/i.test(await page.textContent("#termSub")));
  ok(`${name}: WS-1 stays ready (no collector ran in the AI-to-OT scenario)`, await page.evaluate(() => [...document.querySelectorAll("#boardBody tr")].some((r) => r.textContent.includes("WS-1") && r.querySelector(".st.idle"))));
  ok(`${name}: the embedded console shows the AI-to-OT alarms`, (await page.frameLocator("#frame").locator(".chip.demo").textContent()).toLowerCase().includes("synthetic"));
  await shot("ai-ot");
  await page.click('[data-lang="de"]'); await sleep(400);
  ok(`${name}: DE labels the finished AI-to-OT replay, the other button and the board tag`, (await page.textContent("#replayAiLabel")).includes("Erneut") && (await page.textContent("#replayLabel")).includes("Angriff abspielen") && /synthetisch/i.test(await page.textContent("#boardTag")) && /synthetisch/i.test(await page.textContent("#termSub")));
  await page.click('[data-lang="en"]');
  // changing the embedded console's scenario list resets the page: after a finished replay, and in the middle of one
  const sel = page.frameLocator("#frame").locator(".demo-bar select");
  const idle = async () => (await page.textContent("#replayLabel")).includes("Replay the attack") && (await page.textContent("#replayAiLabel")).includes("AI-to-OT") && !(await page.textContent("#replayAiLabel")).includes("again") && !(await page.$("#replay:disabled, #replayAi:disabled")) && /lab/i.test(await page.textContent("#termSub"));
  await sel.selectOption("lab"); await sleep(700);
  ok(`${name}: switching scenario after a finished replay returns the page to idle (no stale "Replay again")`, await idle());
  await page.click("#replayAi"); await sleep(2500);
  await sel.selectOption("lab"); await sleep(700);
  ok(`${name}: switching scenario mid-replay re-enables both buttons and clears the board`, await idle() && !(await page.$("#boardBody .fresh")));

  // the recordings: four chapters, each loads and plays
  ok(`${name}: four chapters listed`, (await page.$$("#chapters button")).length === 4);
  for (let i = 0; i < 4; i++) {
    await page.locator("#chapters button").nth(i).click();
    const v = await page.evaluate(async () => {
      const el = document.querySelector("#player"); el.muted = true;
      await new Promise((r) => { if (el.readyState >= 2) r(); else { el.onloadeddata = r; setTimeout(r, 9000); } });
      let played = false; try { await el.play(); await new Promise((r) => setTimeout(r, 1200)); played = el.currentTime > 0.4; el.pause(); } catch (e) { played = String(e); }
      return { src: document.querySelector("#playerSrc").getAttribute("src"), ready: el.readyState, dur: Math.round(el.duration), w: el.videoWidth, played };
    });
    ok(`${name}: chapter ${i + 1} (${v.src.split("/").pop()}) loads and plays`, v.ready >= 2 && v.dur >= 45 && v.w === 1280 && v.played === true, JSON.stringify(v));
  }
  ok(`${name}: no uncaught errors`, errs.length === 0, errs.join(" | "));
  await ctx.close();
}
await b.close();
const bad = res.filter((r) => !r).length;
console.log(`${res.length - bad}/${res.length} passed`);
process.exit(bad ? 1 : 0);
