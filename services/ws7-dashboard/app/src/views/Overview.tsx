import { mitreTags } from "../data/api";
import { AlarmShape, Bars, Mimic, Panel, Trend } from "../hmi/hmi";
import { unit } from "../lib/i18n";
import { pipelineStages } from "../lib/ops";
import { isAbnormal, priority, rank } from "../lib/severity";
import { ago, bucket, fmtTime } from "../lib/time";
import { triageOf, useConsole } from "../store";

const N = 48;
const PRIOS = ["critical", "high", "medium", "low"] as const;
const PRIO_FILL: Record<string, string> = { critical: "var(--red)", high: "var(--amber)", medium: "var(--yellow)", low: "var(--slate)" };

export function Overview({ go }: { go: (hash: string) => void }) {
  const { t, lang, data, from, to, triage } = useConsole();
  const rules = data.rules;
  const alerts = data.alerts?.ok ? data.alerts.data : [];
  const events = data.events?.ok ? data.events.data : [];
  const stages = pipelineStages(t, data.ops, rules, alerts, events);

  const active = alerts
    .filter((a) => isAbnormal(a.level, triageOf(a, triage).status))
    .sort((a, b) => rank(b.level) - rank(a.level) || b.time - a.time);
  const alarmTimes = active.map((a) => a.time);

  const mix = new Map<string, number>();
  for (const a of alerts) { const p = priority(a.level); mix.set(p, (mix.get(p) || 0) + 1); }
  const sources = new Map<string, number>();
  for (const e of events) { const s = e.siem?.source_type || "unknown"; sources.set(s, (sources.get(s) || 0) + 1); }
  const sourceRows = [...sources.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);

  const tacticCounts = new Map<string, number>();
  for (const a of alerts) for (const tac of mitreTags(a.mitre).tactics) tacticCounts.set(tac, (tacticCounts.get(tac) || 0) + 1);
  const ruleTactics = new Set<string>();
  if (rules?.ok) for (const r of rules.data.rules) for (const tac of mitreTags(r.mitre).tactics) ruleTactics.add(tac);
  const tactics = [...new Set([...ruleTactics, ...tacticCounts.keys()])].sort();
  const maxTac = Math.max(1, ...tacticCounts.values());
  const heat = (n: number) => (n === 0 ? "" : n / maxTac > 0.66 ? " h3" : n / maxTac > 0.33 ? " h2" : " h1");

  const down = !data.alerts?.ok && data.alerts !== null;

  return (
    <>
      <h1 className="view-title">{t.overview}</h1>
      <div className="grid">
        <Panel title={t.pipeline} aside={data.fetchedAt ? `${t.checked} ${ago(data.fetchedAt, lang)}` : "…"}>
          <Mimic stages={stages} downLabel={t.noMetrics} />
        </Panel>

        <div className="grid g2">
          <Panel title={t.eventRate} aside={`${events.length.toLocaleString()} ${unit(lang, events.length, "events", t.events_)}`}>
            <Trend series={bucket(events.map((e) => e.time), from, to, N)} from={from} to={to} label={t.eventRate} lang={lang} />
          </Panel>
          <Panel title={t.alarmRate} aside={`${alarmTimes.length} ${unit(lang, alarmTimes.length, "alarmsActive", t.alarmsActive)}`}>
            <Trend tone="alarm" series={bucket(alarmTimes, from, to, N)} from={from} to={to} marks={alarmTimes} label={t.alarmRate} lang={lang} />
          </Panel>
        </div>

        <div className="grid g2">
          <Panel title={t.sevMix} aside={`${alerts.length} ${unit(lang, alerts.length, "alarms", t.alarms.toLowerCase())}`}>
            <div className="stack" role="img" aria-label={PRIOS.map((p) => `${p} ${mix.get(p) || 0}`).join(", ")}>
              {PRIOS.map((p) => (mix.get(p) ? <span key={p} style={{ flex: mix.get(p), background: PRIO_FILL[p] }} /> : null))}
            </div>
            <div className="legend">
              {PRIOS.map((p) => <span key={p} className="sev"><AlarmShape level={p} />{p} <b>{mix.get(p) || 0}</b></span>)}
            </div>
          </Panel>
          <Panel title={t.bySource} aside={`${sources.size} ${t.parser.toLowerCase()}`}>
            {sourceRows.length ? <Bars rows={sourceRows} /> : <p className="empty">{t.noData}</p>}
          </Panel>
        </div>

        <div className="grid g2">
          <Panel title={t.latest} aside={active.length ? <a href="#/alarms">{t.alarms} →</a> : t.noAlarms}>
            {down ? (
              <p className="empty"><b>{t.unreachable}.</b> {data.alerts && !data.alerts.ok ? data.alerts.reason : ""}</p>
            ) : active.length === 0 ? (
              <p className="empty"><b className="ok-text">{t.noAlarms}.</b> {alerts.length} {t.alarms.toLowerCase()} {t.of} {rules?.ok ? rules.data.count : "?"} {t.rules}, {t.checked} {ago(data.fetchedAt, lang)}.</p>
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <tbody>
                    {active.slice(0, 8).map((a) => (
                      <tr key={a.alert_id} className="clk" onClick={() => go(`#/alarms/${encodeURIComponent(a.alert_id)}`)}>
                        <td style={{ width: 22 }}><AlarmShape level={a.level} /></td>
                        <td>{a.rule_title}</td>
                        <td className="mono muted" style={{ whiteSpace: "nowrap" }}>{a.src_endpoint?.ip || ""}</td>
                        <td className="muted" style={{ whiteSpace: "nowrap" }}>{fmtTime(a.time, lang)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
          <Panel title={t.tactics} aside={<a href="#/coverage">{tacticCounts.size} / {tactics.length} →</a>}>
            <div className="strip">
              {tactics.map((tac) => (
                <div key={tac} className={`tac${heat(tacticCounts.get(tac) || 0)}`}>
                  <b>{tac}</b>
                  <span className="muted">{tacticCounts.get(tac) || 0} {t.alarms.toLowerCase()}</span>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}
