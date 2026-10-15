import { useEffect, useMemo, useRef, useState } from "react";
import type { OcsfEvent } from "../data/api";
import { Panel } from "../hmi/hmi";
import { ago, fmtTime } from "../lib/time";
import { useConsole } from "../store";
import { S } from "./sources.i18n";

/* Data sources & onboarding. Only mechanisms that exist in the repo:
   - WS-1 UDP syslog listener, default 0.0.0.0:5514 (ws1-collectors/main.py, syslog_udp_server.py);
     every datagram is stamped source_type=generic_syslog, which WS-2 treats as authoritative
     (ws2-normalization/parsers/__init__.py resolve()), so UDP senders arrive as generic_syslog.
   - tools/agent_log_shipper.py: JSONL -> raw.events with any --source-type (structured parsers).
   - WS-6 inventory is MAC-keyed and fed only by assets.updates, so these sources never add devices. */

type DevId = "rsyslog" | "syslogng" | "k8s" | "cloudtrail" | "windows" | "mcp";
interface Device { id: DevId; st: string; usesHost: boolean; snippet: (host: string) => string }

const SHIP_ENV = "export BUS_BACKEND=redis REDIS_URL=redis://127.0.0.1:6379/0\n";
const LOGGER_TEST = 'logger -t fengarde-test "first event from $(hostname)"';

const DEVICES: Device[] = [
  { id: "rsyslog", st: "generic_syslog", usesHost: true, snippet: (h) =>
    `# /etc/rsyslog.d/90-fengarde.conf\n*.* @${h}:5514\n\nsudo systemctl restart rsyslog\n${LOGGER_TEST}` },
  { id: "syslogng", st: "generic_syslog", usesHost: true, snippet: (h) =>
    `# /etc/syslog-ng/conf.d/fengarde.conf\ndestination d_fengarde { network("${h}" port(5514) transport("udp")); };\nlog { source(s_src); destination(d_fengarde); };\n\nsudo systemctl restart syslog-ng\n${LOGGER_TEST}` },
  { id: "k8s", st: "k8s_audit", usesHost: false, snippet: () =>
    `${SHIP_ENV}ssh CONTROL_PLANE 'sudo tail -F /var/log/kubernetes/audit.log' \\\n  | python tools/agent_log_shipper.py --stdin --source-type k8s_audit` },
  { id: "cloudtrail", st: "cloudtrail", usesHost: false, snippet: () =>
    `${SHIP_ENV}gunzip -c CLOUDTRAIL_FILE.json.gz | jq -c '.Records[]' \\\n  | python tools/agent_log_shipper.py --stdin --source-type cloudtrail` },
  { id: "windows", st: "windows_eventlog", usesHost: false, snippet: () =>
    `${SHIP_ENV}python tools/agent_log_shipper.py --file events.jsonl --source-type windows_eventlog` },
  { id: "mcp", st: "mcp_agent", usesHost: false, snippet: () =>
    `${SHIP_ENV}python tools/agent_log_shipper.py --file /path/to/agent.jsonl --follow` },
];

const COUNTERS = [
  "events_produced", "events_dropped", "events_shed", "events_spooled", "events_lost",
  "events_queue_full", "events_empty", "recv_oserror_total", "udp_rcvbuf_errors_cumulative",
] as const;

type PeerStats = { produced?: number; dropped?: number; shed?: number; empty?: number };

// Zabbix-style nodata: a source that sent in this range but nothing for SILENT_MS is flagged.
const SILENT_MS = 15 * 60_000;

const idOf = (e: OcsfEvent) => e.siem?.ingest_id || e.metadata?.uid || `${e.time}|${e.message ?? ""}`;
const sender = (e: OcsfEvent) => e.src_endpoint?.hostname || e.src_endpoint?.ip || "";

export function Sources() {
  const { t, lang, data } = useConsole();
  const s = S[lang];
  const events = useMemo(() => (data.events?.ok ? data.events.data : []), [data.events]);

  const rows = useMemo(() => {
    const m = new Map<string, { n: number; last: number; senders: Map<string, number> }>();
    for (const e of events) {
      const st = e.siem?.source_type || "unknown";
      const r = m.get(st) ?? { n: 0, last: 0, senders: new Map<string, number>() };
      r.n++;
      if (e.time > r.last) r.last = e.time;
      const who = sender(e);
      if (who) r.senders.set(who, (r.senders.get(who) || 0) + 1);
      m.set(st, r);
    }
    return [...m.entries()].sort((a, b) => b[1].n - a[1].n);
  }, [events]);

  return (
    <>
      <h1 className="view-title">{t.sources}<small>{rows.length} {s.types}</small></h1>
      <div className="grid">
        <Flow />
        <div className="grid g2">
          <Connect events={events} />
          <Ws1Health />
        </div>
        <Panel title={t.bySource} aside={`${events.length} ${s.events.toLowerCase()}`}>
          <p className="hint">{s.tableHint}</p>
          {data.events && !data.events.ok ? <p className="empty"><b>{t.unreachable}.</b> {data.events.reason}</p>
            : rows.length === 0 ? <p className="empty">{t.noData}</p> : (
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>{t.source}</th><th className="num">{s.events}</th><th>{t.lastSeen}</th><th>{s.topSenders}</th></tr></thead>
                <tbody>
                  {rows.map(([st, r]) => (
                    <tr key={st}>
                      <td className="mono">{st}</td>
                      <td className="num">{r.n.toLocaleString()}</td>
                      <td className="muted" title={r.last ? fmtTime(r.last, lang) : undefined}>
                        {r.last ? ago(r.last, lang) : "—"}
                        {r.last && data.fetchedAt - r.last > SILENT_MS && <span className="pill warn" style={{ marginLeft: 8 }}>{t.silent}</span>}
                      </td>
                      <td>
                        {[...r.senders.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([who, n]) => (
                          <span key={who} className="tag">{who} · {n.toLocaleString()}</span>
                        ))}
                        {r.senders.size === 0 && "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
        <Panel title={s.limits}>
          <ul className="hint" style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 6 }}>
            {s.limitItems.map((x) => <li key={x}>{x}</li>)}
          </ul>
        </Panel>
      </div>
    </>
  );
}

function Flow() {
  const { lang } = useConsole();
  const s = S[lang];
  return (
    <section className="panel" aria-label={s.flowLabel}>
      <div className="filters" style={{ marginBottom: 6 }}>
        <b style={{ marginRight: 4 }}>{s.flowLabel}</b>
        {s.flow.map((step, i) => (
          <span key={step} style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            {i > 0 && (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                <path d="M5 12h14M13 6l6 6-6 6" />
              </svg>
            )}
            <span className="tag">{step}</span>
          </span>
        ))}
      </div>
      <p className="note">{s.flowNote}</p>
    </section>
  );
}

function Connect({ events }: { events: OcsfEvent[] }) {
  const { t, lang, data } = useConsole();
  const s = S[lang];
  const [devId, setDevId] = useState<DevId | null>(null);
  const [host, setHost] = useState(() => location.hostname || "FENGARDE_HOST");
  const [want, setWant] = useState("");
  const [copied, setCopied] = useState<"" | "ok" | "manual">("");
  const preRef = useRef<HTMLPreElement>(null);

  const dev = DEVICES.find((d) => d.id === devId) || null;
  const snippet = dev ? dev.snippet(host.trim() || "FENGARDE_HOST") : "";
  useEffect(() => setCopied(""), [snippet]);

  const needle = want.trim().toLowerCase();
  const matching = useMemo(() => (dev
    ? events.filter((e) => e.siem?.source_type === dev.st
        && (!needle || [e.src_endpoint?.hostname, e.src_endpoint?.ip].some((v) => v?.toLowerCase() === needle)))
    : []), [dev, events, needle]);

  // Baseline = matching events already loaded when the check (re)starts; only a NEW one counts,
  // so an existing sender of the same type cannot fake a success.
  const key = dev ? `${dev.st}|${needle}` : "";
  const loaded = !!data.events?.ok;
  const [baseline, setBaseline] = useState<{ key: string; ids: Set<string> } | null>(null);
  useEffect(() => {
    if (key && loaded && baseline?.key !== key) setBaseline({ key, ids: new Set(matching.map(idOf)) });
  }, [key, loaded, baseline, matching]);
  const armed = baseline !== null && baseline.key === key;
  const fresh = armed ? matching.find((e) => !baseline.ids.has(idOf(e))) : undefined;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(snippet);
      setCopied("ok");
    } catch {
      // No clipboard API on a non-secure origin (plain http on a LAN): select the text instead.
      const el = preRef.current;
      const sel = window.getSelection();
      if (el && sel) { const r = document.createRange(); r.selectNodeContents(el); sel.removeAllRanges(); sel.addRange(r); }
      setCopied("manual");
    }
  };

  return (
    <Panel title={s.connect}>
      <ol style={{ margin: 0, paddingLeft: 20, display: "grid", gap: 16 }}>
        <li>
          <b>{s.step1}</b>
          <p className="note" style={{ margin: "2px 0 8px" }}>{s.step1Hint}</p>
          <div className="seg" role="group" aria-label={s.deviceType} style={{ flexWrap: "wrap" }}>
            {DEVICES.map((d) => (
              <button key={d.id} type="button" aria-pressed={d.id === devId} onClick={() => setDevId(d.id)}>{s.devices[d.id].name}</button>
            ))}
          </div>
        </li>

        <li>
          <b>{s.step2}</b>
          {!dev ? <p className="note">{s.pickFirst}</p> : (
            <div style={{ display: "grid", gap: 8, marginTop: 8 }}>
              {dev.usesHost && (
                <label style={{ display: "grid", gap: 4, fontSize: 13 }}>
                  {s.hostLabel}
                  <input className="ctl mono" value={host} onChange={(e) => setHost(e.target.value)} spellCheck={false} />
                </label>
              )}
              <pre className="raw" ref={preRef}>{snippet}</pre>
              <div className="filters" style={{ marginBottom: 0 }}>
                <button type="button" className="btn primary" onClick={copy}>{s.copy}</button>
                <span className="note" style={{ margin: 0 }} aria-live="polite">{copied === "ok" ? s.copied : copied === "manual" ? s.copyManual : ""}</span>
              </div>
              <p className="note">{s.devices[dev.id].note}{!dev.usesHost && <> {s.shipperNote}</>}</p>
              <p className="note">{s.arrivesAs} <span className="tag">{dev.st}</span></p>
            </div>
          )}
        </li>

        <li>
          <b>{s.step3}</b>
          {!dev ? <p className="note">{s.pickFirst}</p> : (
            <div style={{ display: "grid", gap: 8, marginTop: 8 }}>
              <label style={{ display: "grid", gap: 4, fontSize: 13 }}>
                {s.wantLabel}
                <input className="ctl mono" value={want} onChange={(e) => setWant(e.target.value)} spellCheck={false} />
              </label>
              <div aria-live="polite">
                {data.events && !data.events.ok ? <p className="empty"><b>{t.unreachable}.</b> {data.events.reason}</p>
                  : !armed ? <p className="note">{s.notLoaded}</p>
                  : fresh ? (
                    <p style={{ margin: 0 }}>
                      <span className="pill ok">{s.received}</span>{" "}
                      <span className="mono">{dev.st}</span>
                      {sender(fresh) && <> {s.from} <span className="mono">{sender(fresh)}</span></>}
                      {" · "}<span className="muted">{fmtTime(fresh.time, lang)}</span>
                    </p>
                  ) : (
                    <>
                      <p style={{ margin: 0 }}><span className="pill off">{s.waiting(dev.st)}</span></p>
                      <p className="note">{s.lastCheck}: {data.fetchedAt ? ago(data.fetchedAt, lang) : "—"}{baseline.ids.size > 0 && <> · {s.already(baseline.ids.size)}</>}</p>
                    </>
                  )}
              </div>
              <p className="note">{s.invNote} <a href="#/inventory">{s.invLink}</a></p>
            </div>
          )}
        </li>
      </ol>
    </Panel>
  );
}

function Ws1Health() {
  const { t, lang, data } = useConsole();
  const s = S[lang];
  const m = data.ops.ws1;
  const extra: Record<string, unknown> = m?.ok ? m.data.extra || {} : {};
  const num = (k: string) => (typeof extra[k] === "number" ? (extra[k] as number) : undefined);
  const silence = num("seconds_since_last_event");
  const rawPeers = extra.per_source;
  const peers = Object.entries((rawPeers && typeof rawPeers === "object" ? rawPeers : {}) as Record<string, PeerStats>)
    .sort((a, b) => (b[1].produced || 0) - (a[1].produced || 0));

  return (
    <Panel title={s.health}>
      {m === undefined ? <p className="empty">…</p>
        : !m.ok ? <p className="empty"><b>{s.noMetrics}.</b> {m.reason}</p>
        : num("events_produced") === undefined ? <p className="empty">{s.noListener}</p> : (
        <>
          <dl className="kv">
            {COUNTERS.map((k) => {
              const v = num(k);
              if (v === undefined) return null;
              // Any non-zero loss/error counter is abnormal; produced is the throughput itself.
              const bad = k !== "events_produced" && k !== "events_spooled" && v > 0;
              return [
                <dt key={`${k}-t`}>{s.counters[k]}</dt>,
                <dd key={`${k}-d`} className="mono" style={bad ? { color: "var(--amber)", fontWeight: 600 } : undefined}>{v.toLocaleString()}</dd>,
              ];
            })}
            {silence !== undefined && (
              <>
                <dt>{s.silence}</dt>
                <dd title={s.silenceNote}>{ago(Date.now() - silence * 1000, lang)}</dd>
              </>
            )}
          </dl>
          <p className="note">{s.healthNote} {silence !== undefined && s.silenceNote}</p>
          <h3 style={{ fontSize: 13.5, margin: "14px 0 6px" }}>{s.perSender}</h3>
          {peers.length === 0 ? <p className="empty">{s.noSenders}</p> : (
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>{t.ip}</th><th className="num">{s.produced}</th><th className="num">{s.dropped}</th><th className="num">{s.shed}</th><th className="num">{s.empty}</th></tr></thead>
                <tbody>
                  {peers.map(([ip, p]) => (
                    <tr key={ip}>
                      <td className="mono">{ip}</td>
                      <td className="num">{(p.produced || 0).toLocaleString()}</td>
                      <td className="num">{(p.dropped || 0).toLocaleString()}</td>
                      <td className="num">{(p.shed || 0).toLocaleString()}</td>
                      <td className="num">{(p.empty || 0).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </Panel>
  );
}
