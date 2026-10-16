// End-to-end MFA through the real UI: enrol a throwaway user, then sign in WITH the TOTP code via the form.
import crypto from "node:crypto";
import { BASE, creds, launch, login, sleep } from "./lib.mjs";

const C = creds();
const results = [];
const ok = (n, c, x = "") => { results.push(c); console.log(`${c ? "[ok]  " : "[FAIL]"} ${n}${!c && x ? "  " + x : ""}`); };

const b32 = (s) => { const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = ""; for (const ch of s.toUpperCase().replace(/=+$/, "")) bits += A.indexOf(ch).toString(2).padStart(5, "0"); const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); };
const totp = (secret, at = Date.now()) => {
  const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(Math.floor(at / 30000)));
  const h = crypto.createHmac("sha1", b32(secret)).update(buf).digest();
  const o = h[h.length - 1] & 15;
  return String(((h.readUInt32BE(o) & 0x7fffffff) % 1e6)).padStart(6, "0");
};

const browser = await launch();
const stamp = Date.now() % 1e6;
const user = `ui-mfa-${stamp}`, pw = `Mfa-${stamp}-Rt5!wQxZ`;

// admin creates the user
const actx = await browser.newContext();
const apage = await actx.newPage();
await login(apage, C.admin);
const csrf = (await (await apage.request.get(`${BASE}/api/auth/me`)).json()).csrf_token;
const mk = await apage.request.post(`${BASE}/api/triage/users`, { data: { username: user, password: pw, role: "read_only" }, headers: { "X-CSRF-Token": csrf } });
ok("admin creates the throwaway user", mk.status() === 201, String(mk.status()));

// the user enrols MFA (API, the same calls the Account page makes)
const uctx = await browser.newContext();
const upage = await uctx.newPage();
await login(upage, [user, pw]);
const ucsrf = (await (await upage.request.get(`${BASE}/api/auth/me`)).json()).csrf_token;
const en = await upage.request.post(`${BASE}/api/auth/mfa/enable`, { data: { password: pw }, headers: { "X-CSRF-Token": ucsrf } });
const enBody = await en.json().catch(() => ({}));
console.log("enable status", en.status(), Object.keys(enBody).join(","), enBody.error || "");
const uri = enBody.otpauth_uri || "otpauth://totp/x?secret=";
const secret = new URL(uri.replace("otpauth://", "http://")).searchParams.get("secret");
ok("MFA enrolment returns a secret", !!secret);
const ver = await upage.request.post(`${BASE}/api/auth/mfa/verify`, { data: { password: pw, totp_code: totp(secret) }, headers: { "X-CSRF-Token": ucsrf } });
ok("MFA verified and active", ver.status() === 200, String(ver.status()));
await uctx.close();

// sign in through the real form
const fctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: "en-GB" });
const fpage = await fctx.newPage();
await fpage.goto(BASE + "/"); await fpage.waitForSelector("#u");
await fpage.fill("#u", user); await fpage.fill("#p", pw);
await fpage.click("form button.btn.primary");
await fpage.waitForFunction(() => document.querySelector(".err")?.textContent.trim().length > 0, null, { timeout: 8000 }).catch(() => {});
console.log("err text:", JSON.stringify(await fpage.textContent(".err")), "nav?", !!(await fpage.$(".nav a[href='#/alarms']")), "url", fpage.url());
ok("MFA account without a code is refused", !(await fpage.$(".nav a[href='#/alarms']")) && (await fpage.textContent(".err")).includes("Sign-in failed"));
// the code spent on enrolment cannot be replayed in the same 30 s window (WS-3 replay protection): wait for the next one
await sleep(30000 - (Date.now() % 30000) + 1500);
await fpage.fill("#c", totp(secret));
await fpage.click("form button.btn.primary");
await fpage.waitForSelector(".nav a[href='#/alarms']", { timeout: 10000 }).catch(() => {});
console.log("after code: err", JSON.stringify(await fpage.textContent(".err").catch(() => null)), "code len", (await fpage.inputValue("#c").catch(() => "")).length);
ok("MFA account signs in with the code typed into the form", !!(await fpage.$(".nav a[href='#/alarms']")));
ok("signed in as the MFA user", (await fpage.textContent(".chip.user")).includes(user));
await fctx.close();

// cleanup: disable the throwaway account
const dis = await apage.request.patch(`${BASE}/api/triage/users/${user}`, { data: { disabled: true }, headers: { "X-CSRF-Token": csrf } });
ok("throwaway user disabled afterwards", dis.status() === 200);
await browser.close();
const bad = results.filter((r) => !r).length;
console.log(`\n${results.length - bad}/${results.length} passed`);
process.exit(bad ? 1 : 0);
