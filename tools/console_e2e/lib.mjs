// Shared helpers. Credentials are read in-process from a gitignored env file and never printed.
import { chromium } from "playwright-core";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const REPO = path.resolve(here, "../..");
export const BASE = process.env.FENGARDE_URL || "http://127.0.0.1:8080";
export const ENV = process.env.FENGARDE_ENV_FILE || path.join(REPO, "infra", ".env.local-test");
export const OUT = process.env.FENGARDE_E2E_OUT || path.join(here, "out");
export const ROUTES = ["overview", "alarms", "incidents", "events", "coverage", "sources", "inventory", "operations", "audit", "account", "settings"];

/** admin / analyst / read-only test accounts from the env file (FENGARDE_TEST_{ADMIN,ANALYST,READONLY}_{USER,PASSWORD}). */
export function creds() {
  if (!fs.existsSync(ENV)) {
    throw new Error(`test-account env file not found: ${ENV}\nSet FENGARDE_ENV_FILE, or create it (see tools/console_e2e/README.md).`);
  }
  const cfg = Object.fromEntries(fs.readFileSync(ENV, "utf8").split(/\r?\n/).filter((l) => l.includes("=") && !l.startsWith("#")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
  return {
    admin: [cfg.FENGARDE_TEST_ADMIN_USER, cfg.FENGARDE_TEST_ADMIN_PASSWORD],
    analyst: [cfg.FENGARDE_TEST_ANALYST_USER, cfg.FENGARDE_TEST_ANALYST_PASSWORD],
    readonly: [cfg.FENGARDE_TEST_READONLY_USER, cfg.FENGARDE_TEST_READONLY_PASSWORD],
  };
}

const CHROME = [
  process.env.CHROME_PATH,
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
].filter(Boolean).find((p) => fs.existsSync(p));

export async function launch() {
  if (!CHROME) throw new Error("no Chrome/Chromium found: set CHROME_PATH");
  return chromium.launch({ executablePath: CHROME, headless: true });
}

export async function login(page, [user, pw]) {
  await page.goto(BASE + "/", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("#u");
  await page.fill("#u", user);
  await page.fill("#p", pw);
  await page.click("form button.btn.primary");
  await page.waitForSelector('.nav a[href="#/alarms"]', { timeout: 15000 });
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
