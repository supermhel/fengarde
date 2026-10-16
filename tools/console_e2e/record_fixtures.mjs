// Records the console's demo fixtures from a LIVE stack: every GET the console makes, plus the generated reports.
// Output: services/ws7-dashboard/app/src/demo/fixtures.json (a recording of lab data; the demo build serves it).
//
//   node record_fixtures.mjs [attacker_ip]      default attacker 203.0.113.50
//
// Run order (what the demo's "Replay the attack" replays):
//   1. python tools/console_tour_traffic.py 127.0.0.1 5514 <attacker_ip>      (once, then wait ~45 s)
//   2. node record_fixtures.mjs <attacker_ip>
// Earlier high alarms from other lab runs should already be closed so the demo's idle state is quiet.
import fs from "node:fs";
import path from "node:path";
import { BASE, REPO, creds, launch, login } from "./lib.mjs";

const attacker = process.argv[2] || "203.0.113.50";
const out = path.join(REPO, "services", "ws7-dashboard", "app", "src", "demo", "fixtures.json");

const browser = await launch();
const ctx = await browser.newContext();
const page = await ctx.newPage();
await login(page, creds().admin);
const csrf = (await (await page.request.get(`${BASE}/api/auth/me`)).json()).csrf_token;
const get = async (p) => { const r = await page.request.get(BASE + p); return r.ok() ? r.json() : null; };
const post = async (p) => { const r = await page.request.post(BASE + p, { data: {}, headers: { "X-CSRF-Token": csrf } }); return r.ok() ? r.json() : null; };

const T = "tenant_id=default";
const alerts = await get("/api/alerts?gte=0");
const events = await get("/api/events?gte=0");
const hitsOf = (r) => (r?.hits?.hits || []).map((h) => h._source);
const atkAlerts = hitsOf(alerts).filter((a) => a.src_endpoint?.ip === attacker);
const atkEvents = hitsOf(events).filter((e) => e.src_endpoint?.ip === attacker);
if (!atkAlerts.length || !atkEvents.length) throw new Error(`no alerts/events from ${attacker}: send the attack first (see header)`);
const t0 = Math.min(...atkEvents.map((e) => e.time));

const incidents = await get(`/api/incidents?${T}`);
const fx = {
  meta: {
    recordedAt: Date.now(), attacker, t0,
    note: "Recorded from a local lab stack fed with tools/console_tour_traffic.py. Lab data, not a real attack.",
    attackAlerts: atkAlerts.length, attackEvents: atkEvents.length,
  },
  alerts, events,
  ai: await get("/api/ai-triage"),
  incidents,
  rules: await get(`/api/rules?${T}`),
  assets: await get(`/api/inventory/assets?limit=200&${T}`),
  keys: await get("/api/inventory/keys"),
  audit: await get("/api/audit?limit=200"),
  users: await get("/api/triage/users"),
  webhooks: await get("/api/triage/webhooks"),
  ops: {}, asset: {}, graph: {}, evidence: {}, entity: {}, incidentReport: {}, reports: {},
};
for (const k of ["ws1", "ws2", "ws3", "ws4", "ws5", "ws8"]) fx.ops[k] = await get(`/api/ops/${k}`);
for (const a of fx.assets || []) fx.asset[a.mac] = await get(`/api/inventory/assets/${encodeURIComponent(a.mac)}?${T}`);

for (const inc of incidents?.incidents || []) {
  const id = inc.incident_id;
  fx.graph[id] = await get(`/api/incidents/${encodeURIComponent(id)}/graph?${T}`);
  fx.evidence[id] = await get(`/api/incidents/${encodeURIComponent(id)}/evidence?${T}`);
  for (const lg of ["en", "de"]) fx.incidentReport[`${id}|${lg}`] = await post(`/api/incidents/${encodeURIComponent(id)}/report?lang=${lg}&${T}`);
  for (const n of fx.graph[id]?.nodes || []) {
    if (!fx.entity[n.entity_id]) fx.entity[n.entity_id] = await get(`/api/entities/${encodeURIComponent(n.entity_id)}?${T}`);
  }
}
// reports for the attack's own alarms: the plain report and the NIS2 draft per stage and language
const QUERIES = ["", ...["early_warning", "notification", "final_report"].flatMap((s) => ["de", "en"].map((l) => `?template=nis2&stage=${s}&lang=${l}`))];
for (const a of atkAlerts) {
  for (const q of QUERIES) fx.reports[`${a.alert_id}|${q}`] = await post(`/api/triage/alerts/${encodeURIComponent(a.alert_id)}/report${q}`);
}
// the audit trail is recorded as the last 40 entries: the earlier ones are test-harness noise
if (fx.audit?.entries) fx.audit = { ...fx.audit, entries: fx.audit.entries.slice(0, 40), count: Math.min(40, fx.audit.entries.length) };

fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, JSON.stringify(fx));
await browser.close();
console.log(`recorded ${out}`);
console.log(`  attacker ${attacker}: ${atkAlerts.length} alarms, ${atkEvents.length} events, t0 ${new Date(t0).toISOString()}`);
console.log(`  ${hitsOf(alerts).length} alerts, ${hitsOf(events).length} events, ${(incidents?.incidents || []).length} incidents, ${fx.assets?.length} assets, ${Object.keys(fx.reports).length} reports; ${(fs.statSync(out).size / 1024).toFixed(0)} KB`);
