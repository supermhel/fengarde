// Recording machinery shared by the chapter scripts: a visible pointer, human-paced typing and clicking, a screencast
// of the page, and encoding with the system ffmpeg. Local lab stacks only (the chapters create users and devices).
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { BASE, creds, launch, sleep } from "./lib.mjs";

const W = 1280, H = 720;

export async function record(name, outDir, run, opts = {}) {
  const C = creds();
  fs.mkdirSync(outDir, { recursive: true });
  const browser = await launch();
  const ctx = await browser.newContext({ viewport: { width: W, height: H }, locale: opts.locale || "en-GB", colorScheme: "light" });
  await ctx.addInitScript(() => {
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
  const cdp = await ctx.newCDPSession(page);
  const frames = [];
  cdp.on("Page.screencastFrame", async ({ data, metadata, sessionId }) => {
    frames.push({ t: metadata.timestamp, data });
    await cdp.send("Page.screencastFrameAck", { sessionId }).catch(() => {});
  });
  await cdp.send("Page.startScreencast", { format: "jpeg", quality: 82, maxWidth: W, maxHeight: H, everyNthFrame: 1 });

  const glide = (x, y, steps = 24) => page.mouse.move(x, y, { steps });
  const clickOn = async (loc, pause = 700) => {
    await loc.scrollIntoViewIfNeeded().catch(() => {});
    const bb = await loc.boundingBox();
    if (!bb) return false;
    await glide(bb.x + bb.width / 2, bb.y + bb.height / 2);
    await sleep(250); await page.mouse.down(); await page.mouse.up(); await sleep(pause);
    return true;
  };
  const typeInto = async (sel, text, delay = 70) => { await clickOn(page.locator(sel), 200); await page.keyboard.type(text, { delay }); };
  const go = async (r, ms = 1800) => { await page.goto(`${BASE}/#/${r}`); await sleep(ms); };
  const nav = (r, ms = 2200) => clickOn(page.locator(`.nav a[href="#/${r}"]`), ms);
  const signIn = async (who, o = {}) => {
    await page.goto(BASE + "/"); await page.waitForSelector("#u"); await sleep(o.look ?? 1200);
    await typeInto("#u", C[who][0], o.fast ? 35 : 70);
    await typeInto("#p", C[who][1], o.fast ? 30 : 60);
    await sleep(350);
    await clickOn(page.locator("form button.btn.primary"), 300);
    await page.waitForSelector('.nav a[href="#/alarms"]', { timeout: 20000 });
    await sleep(o.after ?? 1800);
  };
  const signOut = () => clickOn(page.locator('.top button:has-text("Sign out")'), 1200);

  await run({ page, ctx, C, sleep, glide, clickOn, typeInto, go, nav, signIn, signOut });

  await sleep(900);
  await cdp.send("Page.stopScreencast").catch(() => {});
  await ctx.close();
  await browser.close();

  const dir = `${outDir}/${name}-frames`;
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  const lines = [];
  frames.forEach((f, i) => {
    const file = `f${String(i).padStart(5, "0")}.jpg`;
    fs.writeFileSync(`${dir}/${file}`, Buffer.from(f.data, "base64"));
    const next = frames[i + 1]?.t ?? f.t + 1;
    lines.push(`file '${dir}/${file}'`, `duration ${Math.max(0.02, next - f.t).toFixed(3)}`);
  });
  lines.push(`file '${dir}/f${String(frames.length - 1).padStart(5, "0")}.jpg'`);
  fs.writeFileSync(`${outDir}/${name}-frames.txt`, lines.join("\n"));
  const mp4 = `${outDir}/${name}.mp4`;
  execFileSync("ffmpeg", ["-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", `${outDir}/${name}-frames.txt`,
    "-vf", "fps=25,scale=1280:720,format=yuv420p", "-c:v", "libx264", "-crf", "29", "-preset", "slow", "-movflags", "+faststart", "-an", mp4]);
  const dur = Number(execFileSync("ffprobe", ["-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", mp4]).toString().trim());
  execFileSync("ffmpeg", ["-y", "-loglevel", "error", "-ss", String(opts.posterAt ?? dur * 0.45), "-i", mp4, "-frames:v", "1", "-q:v", "4", `${outDir}/${name}.jpg`]);
  fs.rmSync(dir, { recursive: true, force: true });
  console.log(`recorded ${name}: ${frames.length} frames, ${dur.toFixed(1)} s, ${(fs.statSync(mp4).size / 1024).toFixed(0)} KB`);
  return { mp4, seconds: dur };
}
