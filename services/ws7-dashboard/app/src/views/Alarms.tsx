import { useEffect, useMemo, useState } from "react";
import { api, mitreTags, type Alert, type OcsfEvent } from "../data/api";
import { AlarmShape, Sev } from "../hmi/hmi";
import { isAbnormal, priority } from "../lib/severity";
import { downloadText } from "../lib/download";
import { fmtTime } from "../lib/time";
import { triageOf, useConsole } from "../store";

const STATUSES = ["new", "triaged", "true_positive", "false_positive", "closed"];
type Filter = { scope: "open" | "all"; q: string; sev: string; status: string };
type Saved = Filter & { name: string };
const EMPTY: Filter = { scope: "open", q: "", sev: "", status: "" };

function loadSaved(): Saved[] {
  try { return JSON.parse(localStorage.getItem("fg.filters") || "[]"); } catch { return []; }
}

export function Alarms({ selected, go }: { selected?: string; go: (hash: string) => void }) {
  const { t, lang, data, triage } = useConsole();
  const [f, setF] = useState<Filter>(EMPTY);
  const [saved, setSaved] = useState<Saved[]>(loadSaved);
  const alerts = data.alerts?.ok ? data.alerts.data : [];
  const rows = useMemo(() => {
    const q = f.q.trim().toLowerCase();
    return alerts.filter((a) => {
      const st = triageOf(a, triage).status;
      if (f.scope === "open" && (st === "closed" || st === "false_positive")) return false;
      if (f.sev && priority(a.level) !== f.sev) return false;
      if (f.status && st !== f.status) return false;
      if (q && ![a.rule_title, a.alert_id, a.rule_id, a.sector, a.src_endpoint?.ip, a.actor?.user?.name].some((v) => v?.toLowerCase().includes(q))) return false;
      return true;
    }).sort((a, b) => b.time - a.time);
  }, [alerts, f, triage]);
  const current = alerts.find((a) => a.alert_id === selected);

  function persist(next: Saved[]) {
    setSaved(next);
    try { localStorage.setItem("fg.filters", JSON.stringify(next)); } catch { /* storage blocked: kept for this tab */ }
  }

  // j/k move the selection; the selection opens the detail panel.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement)?.closest("input, textarea, select")) return;
      const i = rows.findIndex((a) => a.alert_id === selected);
      if (e.key === "j" || e.key === "ArrowDown") { const n = rows[Math.min(rows.length - 1, i + 1)]; if (n) go(`#/alarms/${encodeURIComponent(n.alert_id)}`); e.preventDefault(); }
      if (e.key === "k" || e.key === "ArrowUp") { const n = rows[Math.max(0, i - 1)]; if (n) go(`#/alarms/${encodeURIComponent(n.alert_id)}`); e.preventDefault(); }
      if (e.key === "Escape") go("#/alarms");
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [rows, selected, go]);

  const statusLabel = (s: string) => (s === "true_positive" ? t.truePositive : s === "false_positive" ? t.falsePositive : s);

  return (
    <>
      <h1 className="view-title">{t.alarms}<small>{rows.length} / {alerts.length}</small></h1>
      <div className="split">
        <section className="panel">
          <div className="filters">
            <span className="seg">
              <button aria-pressed={f.scope === "open"} onClick={() => setF({ ...f, scope: "open" })}>{t.open}</button>
              <button aria-pressed={f.scope === "all"} onClick={() => setF({ ...f, scope: "all" })}>{t.all}</button>
            </span>
            <input className="ctl" type="search" aria-label={t.search} placeholder={t.search} value={f.q} onChange={(e) => setF({ ...f, q: e.target.value })} />
            <select className="ctl" aria-label={t.level} value={f.sev} onChange={(e) => setF({ ...f, sev: e.target.value })}>
              <option value="">{t.allSev}</option>
              {["critical", "high", "medium", "low"].map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
            <select className="ctl" aria-label={t.status} value={f.status} onChange={(e) => setF({ ...f, status: e.target.value })}>
              <option value="">{t.allStatus}</option>
              {STATUSES.map((s) => <option key={s} value={s}>{statusLabel(s)}</option>)}
            </select>
            <button className="btn" onClick={() => {
              const name = window.prompt(t.filterName);
              if (name) persist([...saved.filter((s) => s.name !== name), { ...f, name }]);
            }}>{t.saveFilter}</button>
            {saved.length > 0 && (
              <select className="ctl" aria-label={t.saved} value="" onChange={(e) => { const s = saved.find((x) => x.name === e.target.value); if (s) setF({ scope: s.scope, q: s.q, sev: s.sev, status: s.status }); }}>
                <option value="">{t.saved}…</option>
                {saved.map((s) => <option key={s.name} value={s.name}>{s.name}</option>)}
              </select>
            )}
            {(f.q || f.sev || f.status || f.scope !== "open") && <button className="btn" onClick={() => setF(EMPTY)}>{t.clear}</button>}
          </div>
          <p className="hint">{t.lifecycle}</p>
          {data.alerts && !data.alerts.ok ? (
            <p className="empty"><b>{t.unreachable}.</b> {data.alerts.reason}</p>
          ) : rows.length === 0 ? (
            <p className="empty">{t.noData}</p>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>{t.level}</th><th>{t.rule}</th><th>{t.source}</th><th className="num">{t.score}</th><th>{t.status}</th><th>{t.time}</th></tr></thead>
                <tbody>
                  {rows.map((a) => {
                    const st = triageOf(a, triage).status;
                    const tags = mitreTags(a.mitre);
                    return (
                      <tr key={a.alert_id} className="clk" aria-selected={a.alert_id === selected} onClick={() => go(`#/alarms/${encodeURIComponent(a.alert_id)}`)}>
                        <td><Sev level={a.level} /></td>
                        <td>
                          {a.rule_title}
                          <div>{tags.tactics.map((x) => <span key={x} className="tag tac-t">{x}</span>)}{tags.techniques.map((x) => <span key={x} className="tag">{x}</span>)}</div>
                        </td>
                        <td className="mono">{a.src_endpoint?.ip || a.actor?.user?.name || ""}</td>
                        <td className="num">{a.score ?? ""}</td>
                        <td><span className={`pill${st === "new" ? " new" : ""}`}>{isAbnormal(a.level, st) && st === "new" ? <b>{statusLabel(st)}</b> : statusLabel(st)}</span></td>
                        <td className="muted" style={{ whiteSpace: "nowrap" }}>{fmtTime(a.time, lang)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
        {current ? <AlarmFaceplate key={current.alert_id} a={current} statusLabel={statusLabel} /> : (
          <aside className="faceplate"><p className="empty">{t.select}</p><p className="note">j / k, Esc</p></aside>
        )}
      </div>
    </>
  );
}

const PLATE: Record<string, string> = { critical: " crit", high: " high", medium: " med", low: "" };

function AlarmFaceplate({ a, statusLabel }: { a: Alert; statusLabel: (s: string) => string }) {
  const { t, lang, data, session, rbac, triage, setLocalTriage } = useConsole();
  const cur = triageOf(a, triage);
  const [note, setNote] = useState(cur.note);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [mode, setMode] = useState<"msg" | "ocsf">("msg");
  const [report, setReport] = useState<{ title: string; body: string } | null>(null);
  const [stage, setStage] = useState("notification");
  const [rlang, setRlang] = useState<"de" | "en">(lang);
  const readOnly = rbac && session?.role === "read_only";
  const tags = mitreTags(a.mitre);
  const events = data.events?.ok ? data.events.data : [];
  const matched: OcsfEvent[] = events.filter((e) => e.siem?.ingest_id && (a.event_ids || []).includes(e.siem.ingest_id));
  const ai = a.ai;

  async function save(status: string) {
    setBusy(true); setErr("");
    const r = await api.setTriage(a.alert_id, status, note);
    if (r.ok) setLocalTriage(a.alert_id, { status: r.data.status, note: r.data.note ?? note });
    else setErr(`${r.status || ""} ${r.reason}`.trim());
    setBusy(false);
  }
  async function runReport(nis2: boolean, st = stage, lg = rlang) {
    setReport({ title: nis2 ? t.nis2 : t.report, body: "…" });
    const r = await api.report(a.alert_id, nis2 ? `?template=nis2&stage=${st}&lang=${lg}` : "");
    setReport({ title: nis2 ? `${t.nis2} · ${st} · ${lg.toUpperCase()}` : t.report, body: r.ok ? r.data.body || "(empty)" : `${t.unreachable}: ${r.reason}` });
  }

  return (
    <aside className={`faceplate${PLATE[priority(a.level)]}`} aria-label={t.alarms}>
      <h2><AlarmShape level={a.level} size={16} /> {priority(a.level)} · {t.score} {a.score ?? "?"}</h2>
      <h3>{a.rule_title}</h3>
      <dl className="kv">
        <dt>{t.time}</dt><dd>{fmtTime(a.time, lang)}</dd>
        <dt>{t.source}</dt><dd className="mono">{a.src_endpoint?.ip || "—"}{a.dst_endpoint?.ip ? ` → ${a.dst_endpoint.ip}` : ""}</dd>
        <dt>{t.actor}</dt><dd>{a.actor?.user?.name || "—"}</dd>
        <dt>MITRE</dt><dd>{tags.tactics.map((x) => <span key={x} className="tag tac-t">{x}</span>)}{tags.techniques.map((x) => <span key={x} className="tag">{x}</span>)}{!tags.tactics.length && !tags.techniques.length && "—"}</dd>
        <dt>{t.sector}</dt><dd>{a.sector || "—"}{a.tenant_id ? ` · ${t.tenant} ${a.tenant_id}` : ""}</dd>
        <dt>{t.aiTriage}</dt>
        <dd>{ai ? <>{ai.verdict} ({ai.level}) · {t.engine}: <b>{ai.engine || "unknown"}</b>{ai.model ? ` ${ai.model}` : ""}{ai.summary ? <div className="note">{ai.summary}</div> : null}</> : "—"}</dd>
      </dl>

      <h2>{t.status}: {statusLabel(cur.status)}</h2>
      <textarea className="note-in" aria-label={t.note} placeholder={t.note} value={note} onChange={(e) => setNote(e.target.value)} disabled={readOnly} />
      <div className="actions">
        <button className="btn primary" disabled={busy || readOnly} onClick={() => save("triaged")}>{t.ack}</button>
        <button className="btn" disabled={busy || readOnly} onClick={() => save("true_positive")}>{t.truePositive}</button>
        <button className="btn" disabled={busy || readOnly} onClick={() => save("false_positive")}>{t.falsePositive}</button>
        <button className="btn" disabled={busy || readOnly} onClick={() => save("closed")}>{t.close}</button>
      </div>
      {readOnly && <p className="note">{t.readOnly}</p>}
      {err && <p className="err" role="alert">{err}</p>}

      <h2 style={{ marginTop: 16 }}>
        {t.why} · {matched.length}/{(a.event_ids || []).length} {t.events_}
        <span className="aside"><span className="seg">
          <button aria-pressed={mode === "msg"} onClick={() => setMode("msg")}>{t.raw}</button>
          <button aria-pressed={mode === "ocsf"} onClick={() => setMode("ocsf")}>{t.normalized}</button>
        </span></span>
      </h2>
      {matched.length === 0 ? (
        <p className="note">{(a.event_ids || []).length ? t.outside : t.noRefs}</p>
      ) : (
        <pre className="raw">{mode === "msg"
          ? matched.map((e) => `${new Date(e.time).toISOString()}  ${e.siem?.source_type || ""}  ${e.message || "(no message field)"}`).join("\n")
          : JSON.stringify(matched.slice(0, 3), null, 2) + (matched.length > 3 ? `\n… +${matched.length - 3} more` : "")}
        </pre>
      )}

      <h2 style={{ marginTop: 16 }}>{t.report}</h2>
      <div className="actions">
        <button className="btn" onClick={() => runReport(false)}>{t.report}</button>
        <select className="ctl" aria-label="NIS2 stage" value={stage} onChange={(e) => { setStage(e.target.value); if (report) runReport(true, e.target.value); }}>
          <option value="early_warning">{t.earlyWarning}</option>
          <option value="notification">{t.notification}</option>
          <option value="final_report">{t.finalReport}</option>
        </select>
        <select className="ctl" aria-label="NIS2 language" value={rlang} onChange={(e) => { const v = e.target.value as "de" | "en"; setRlang(v); if (report) runReport(true, stage, v); }}>
          <option value="de">DE</option><option value="en">EN</option>
        </select>
        <button className="btn" onClick={() => runReport(true)}>{t.nis2}</button>
      </div>
      {report && <div className="report" aria-live="polite"><b>{report.title}</b>{"\n\n"}{report.body}</div>}
      {report && report.body !== "…" && <div className="actions"><button className="btn" onClick={() => downloadText(`fengarde-${a.alert_id}.md`, `# ${report.title}\n\n${report.body}`)}>{t.download}</button></div>}
      <p className="note mono">{a.alert_id}</p>
    </aside>
  );
}
