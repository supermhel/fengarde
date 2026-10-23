// Regenerates docs/img/og.png: the project page's first screen at 1200x630 (English).
//   python -m http.server 8123 --directory docs     (in another shell)
//   node og_shot.mjs [out.png]
import { launch, sleep } from "./lib.mjs";

const URL = process.env.FENGARDE_PAGES_URL || "http://127.0.0.1:8123/";
const out = process.argv[2] || "../../docs/img/og.png";
const b = await launch();
const ctx = await b.newContext({ viewport: { width: 1200, height: 630 }, locale: "en-GB" });
const page = await ctx.newPage();
await page.goto(URL, { waitUntil: "load" });
await sleep(1500);
await page.screenshot({ path: out });
console.log("wrote", out);
await b.close();
