import { useEffect, useState } from "react";
import { api, type OpsMetrics, type PromEnvelope, type PromTarget, type Result } from "../data/api";
import { Mimic, Panel } from "../hmi/hmi";
import { deadletters, pipelineStages } from "../lib/ops";
import { ago } from "../lib/time";
import { OPS_KEYS, useConsole } from "../store";
import { H } from "./health.i18n";

/* Instant queries per scrape target. A column renders only when its query returns series:
   the FENGARDE runners hand-roll their exposition (services/shared/runner.py render_prometheus)
   and export no process_* metrics today, so CPU/memory stay hidden until a target does. */
const PROM_METRICS = [
  { key: "cpu", q: "rate(process_cpu_seconds_total[5m])", fmt: (v: number) => `${(v * 100).toFixed(1)} %` },
  { key: "memory", q: "process_resident_memory_bytes", fmt: (v: number) => `${(v / 1048576).toFixed(0)} MiB` },
  { key: "rate", q: "sum by (instance) (rate(fengarde_topic_events_total[5m]))", fmt: (v: number) => v.toFixed(2) },
] as const;

interface PromState {
  targets: Result<PromEnvelope<{ activeTargets: PromTarget[] }>>;
  metrics: Partial<Record<(typeof PROM_METRICS)[number]["key"], Map<string, number>>>;
}

function SystemHealth() {
  const { lang, data } = useConsole();
  const h = H[lang];
  const [s, setS] = useState<PromState | null>(null);

  // Re-read on every console poll (fetchedAt ticks every 10 s) instead of a second timer.
  useEffect(() => {
    let live = true;
    (async () => {
      const [targets, ...qs] = await Promise.all([api.promTargets(), ...PROM_METRICS.map((m) => api.promQuery(m.q))]);
      const metrics: PromState["metrics"] = {};
      PROM_METRICS.forEach((m, i) => {
        const r = qs[i];
        if (r.ok && r.data.data.result.length) metrics[m.key] = new Map(r.data.data.result.map((x) => [x.metric.instance, Number(x.value[1])]));
      });
      if (live) setS({ targets, metrics });
    })();
    return () => { live = false; };
  }, [data.fetchedAt]);

  const grafana = <a href={`http://${location.hostname}:3000`} target="_blank" rel="noreferrer" title={h.grafanaNote}>{h.grafana} ↗</a>;
  let body;
  if (!s) body = <p className="note">…</p>;
  else if (!s.targets.ok) body = (
    <>
      <p className="empty"><b>{h.unreachable}.</b> {s.targets.reason}</p>
      <p className="note">{h.unreachableHint} <code className="mono">docker compose -f infra/docker-compose.yml --profile observability up -d</code></p>
    </>
  );
  else if (!s.targets.data.data.activeTargets.length) body = <p className="empty">{h.noTargets}</p>;
  else {
    const cols = PROM_METRICS.filter((m) => s.metrics[m.key]);
    body = (
      <>
        <div className="table-wrap">
          <table className="data">
            <thead><tr>
              <th>{h.job}</th><th>{h.instance}</th><th>{h.health}</th><th>{h.lastScrape}</th>
              {cols.map((m) => <th key={m.key} className="num">{h[m.key]}</th>)}
              <th>{h.lastError}</th>
            </tr></thead>
            <tbody>
              {s.targets.data.data.activeTargets.map((tg) => {
                const inst = tg.labels.instance || tg.scrapeUrl;
                const at = Date.parse(tg.lastScrape); // never-scraped targets report year 0001
                return (
                  <tr key={tg.scrapeUrl}>
                    <td className="mono">{tg.labels.job || "—"}</td>
                    <td className="mono">{inst}</td>
                    <td><span className={`pill ${tg.health === "up" ? "ok" : "off"}`}>{h[tg.health] ?? tg.health}</span></td>
                    <td>{at > 0 ? ago(at, lang) : h.never}</td>
                    {cols.map((m) => {
                      const v = s.metrics[m.key]!.get(inst);
                      return <td key={m.key} className="num">{v == null || !isFinite(v) ? "—" : m.fmt(v)}</td>;
                    })}
                    <td className={tg.lastError ? "err" : "muted"}>{tg.lastError || "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {!s.metrics.cpu && !s.metrics.memory && <p className="note">{h.noProcess}</p>}
      </>
    );
  }
  return (
    <Panel title={h.title} aside={<>{h.sourceNote} · {grafana}</>}>
      {body}
      <p className="note">{h.grafanaNote}</p>
    </Panel>
  );
}

const LABEL: Record<string, string> = {
  ws1: "WS-1 Collectors", ws2: "WS-2 Normalization", ws3: "WS-3 Indexer",
  ws4: "WS-4 Detection", ws5: "WS-5 AI triage", ws8: "WS-8 Correlation",
};

function Value({ v }: { v: unknown }) {
  if (v == null) return <>—</>;
  if (Array.isArray(v)) return <>{v.length ? v.join(", ") : "—"}</>;
  if (typeof v === "object") {
    const e = Object.entries(v as Record<string, unknown>);
    return e.length ? <>{e.map(([k, x]) => <div key={k}>{k}: <Value v={x} /></div>)}</> : <>—</>;
  }
  return <b className="mono">{String(v)}</b>;
}

/* Pipeline monitor + per-service health, every number read from that workstream's own /metrics.
   WS-6 (HTTP inventory API) and WS-7 (this page) are not bus runners and have no /metrics card. */
export function Operations() {
  const { t, lang, data } = useConsole();
  const alerts = data.alerts?.ok ? data.alerts.data : [];
  const events = data.events?.ok ? data.events.data : [];
  const stages = pipelineStages(t, data.ops, data.rules, alerts, events);
  const up = OPS_KEYS.filter((k) => data.ops[k]?.ok).length;

  return (
    <>
      <h1 className="view-title">{t.operations}<small>{up} / {OPS_KEYS.length} {t.healthy}</small></h1>
      <div className="grid">
        <Panel title={t.pipeline} aside={data.fetchedAt ? `${t.checked} ${ago(data.fetchedAt, lang)}` : "…"}>
          <Mimic stages={stages} downLabel={t.noMetrics} />
        </Panel>
        <SystemHealth />
        <div className="svc">
          {OPS_KEYS.map((k) => <ServiceCard key={k} name={LABEL[k]} m={data.ops[k]} />)}
        </div>
      </div>
    </>
  );
}

function ServiceCard({ name, m }: { name: string; m: Result<OpsMetrics> | undefined }) {
  const { t, lang } = useConsole();
  if (!m) return <section className="panel"><h2>{name}</h2><p className="note">…</p></section>;
  if (!m.ok) return <section className="panel down"><h2>{name}</h2><p className="empty"><b>{t.noMetrics}.</b> {m.reason}</p></section>;
  const dl = deadletters(m);
  const failed = Object.values(m.data.topics || {}).reduce((s, r) => s + (r.failed || 0), 0);
  const extras = Object.entries(m.data.extra || {});
  return (
    <section className={`panel${dl || failed ? " warn" : ""}`}>
      <h2>{name}<span className="aside">{dl ? `${dl} ${t.deadLettered}` : <span className="pill ok">{t.healthy}</span>}</span></h2>
      <table className="data">
        <thead><tr><th>{t.topics}</th>{["acked", "failed", "deadlettered"].map((r) => <th key={r} className="num">{r}</th>)}</tr></thead>
        <tbody>
          {Object.entries(m.data.topics || {}).map(([topic, r]) => (
            <tr key={topic}><td className="mono">{topic}</td>{["acked", "failed", "deadlettered"].map((k) => <td key={k} className="num">{(r[k] ?? 0).toLocaleString()}</td>)}</tr>
          ))}
        </tbody>
      </table>
      {extras.length > 0 && (
        <dl className="kv" style={{ marginBottom: 0 }}>
          {extras.map(([k, v]) => {
            const fire = /^rule_last_fired_timestamp:(.+)$/.exec(k);
            return fire && typeof v === "number"
              ? [<dt key={k + "t"}>{t.ruleLastFired}</dt>, <dd key={k + "d"}><span className="muted">{fire[1]}</span> · {new Date(v * 1000).toLocaleString(lang)}</dd>]
              : [<dt key={k + "t"} className="mono" style={{ fontSize: 12 }}>{k}</dt>, <dd key={k + "d"}><Value v={v} /></dd>];
          })}
        </dl>
      )}
    </section>
  );
}
