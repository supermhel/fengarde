// Close every open high/critical alarm (lab history) so the next recording starts from a quiet banner.
// Local lab stacks only: it triages every matching alarm as "closed". node close_alarms.mjs
import { BASE, creds, launch, login } from "./lib.mjs";

const b = await launch();
const ctx = await b.newContext();
const page = await ctx.newPage();
await login(page, creds().admin);
const csrf = (await (await page.request.get(`${BASE}/api/auth/me`)).json()).csrf_token;
const al = await (await page.request.get(`${BASE}/api/alerts?gte=0`)).json();
let n = 0;
for (const h of al.hits?.hits || []) {
  const a = h._source;
  if (["high", "critical"].includes(String(a.level).toLowerCase()) && !["closed", "false_positive"].includes(a.triage?.status)) {
    const r = await page.request.post(`${BASE}/api/triage/alerts/${a.alert_id}/triage`, { data: { status: "closed", note: "lab alarm from an earlier run" }, headers: { "X-CSRF-Token": csrf } });
    if (r.ok()) n++;
  }
}
console.log("closed", n);
await b.close();
