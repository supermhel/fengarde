import { useEffect, useState } from "react";
import { api, type EvidencePackage, type Incident, type IncidentGraph, type Result } from "../data/api";
import { Graph } from "../hmi/hmi";
import { downloadText } from "../lib/download";
import { fmtTime } from "../lib/time";
import { useConsole } from "../store";

export function Incidents({ selected, go }: { selected?: string; go: (hash: string) => void }) {
  const { t, lang, data } = useConsole();
  const res = data.incidents;
  const list = res?.ok ? [...res.data.incidents].sort((a, b) => b.last_seen - a.last_seen) : [];
  const current = list.find((i) => i.incident_id === selected);

  return (
    <>
      <h1 className="view-title">{t.incidents}</h1>
      <div className="split">
        <section className="panel">
          <h2>{list.length} {t.incidents.toLowerCase()}<span className="aside">{t.promoted}</span></h2>
          {res && !res.ok ? (
            <p className="empty"><b>{t.unreachable}.</b> {res.reason}</p>
          ) : list.length === 0 ? (
            <p className="empty"><b>{t.noIncidents}</b> {t.noIncidentsHint}</p>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>{t.entity}</th><th>{t.tactics_}</th><th className="num">{t.members}</th><th className="num">{t.severity}</th><th>{t.lastSeen}</th></tr></thead>
                <tbody>
                  {list.map((i) => (
                    <tr key={i.incident_id} className="clk" aria-selected={i.incident_id === selected} onClick={() => go(`#/incidents/${encodeURIComponent(i.incident_id)}`)}>
                      <td><b>{i.entity_value}</b> <span className="muted">{i.entity_type}</span></td>
                      <td>{i.tactics.map((x) => <span key={x} className="tag tac-t">{x}</span>)}</td>
                      <td className="num">{i.member_count}</td>
                      <td className="num">{i.severity}</td>
                      <td className="muted" style={{ whiteSpace: "nowrap" }}>{fmtTime(i.last_seen, lang)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        {current ? <IncidentFaceplate key={current.incident_id} inc={current} /> : (
          <aside className="faceplate"><p className="empty">{selected && res?.ok ? t.incidentGone : t.select}</p></aside>
        )}
      </div>
    </>
  );
}

function IncidentFaceplate({ inc }: { inc: Incident }) {
  const { t, lang } = useConsole();
  const [graph, setGraph] = useState<Result<IncidentGraph> | null>(null);
  const [evidence, setEvidence] = useState<Result<EvidencePackage> | null | "loading">(null);
  const [entity, setEntity] = useState<{ id: string; r: Result<Record<string, unknown>> | null } | null>(null);
  const [rlang, setRlang] = useState<"de" | "en">(lang);
  const [report, setReport] = useState<string | null>(null);

  async function pick(id: string) {
    setEntity({ id, r: null });
    const r = await api.entity(id);
    setEntity((cur) => (cur?.id === id ? { id, r } : cur)); // a slower answer for an older click never overwrites a newer one
  }
  async function runReport(lg = rlang) {
    setReport("…");
    const r = await api.incidentReport(inc.incident_id, lg);
    setReport(r.ok ? r.data.body || "(empty)" : r.status === 409 ? t.tamper : `${t.unreachable}: ${r.reason}`);
  }

  // Keyed by incident id: the 10 s data refresh re-renders the list but never remounts this
  // faceplate, so a built evidence package stays on screen while the analyst reads it.
  useEffect(() => { api.incidentGraph(inc.incident_id).then(setGraph); }, [inc.incident_id]);

  return (
    <aside className="faceplate" aria-label={t.incidents}>
      <h2>{inc.entity_type} · {inc.member_count} {t.members.toLowerCase()} · {t.severity} {inc.severity}</h2>
      <h3>{inc.entity_value}</h3>
      <dl className="kv">
        <dt>{t.tactics_}</dt><dd>{inc.tactics.map((x) => <span key={x} className="tag tac-t">{x}</span>)}</dd>
        <dt>{t.firstSeen}</dt><dd>{fmtTime(inc.first_seen, lang)}</dd>
        <dt>{t.lastSeen}</dt><dd>{fmtTime(inc.last_seen, lang)}</dd>
        <dt>{t.tenant}</dt><dd>{inc.tenant_id || "—"}{inc.truncated ? ` · ${t.capReached}` : ""}</dd>
        <dt>ID</dt><dd className="mono">{inc.incident_id}</dd>
      </dl>

      <h2>{t.graph}</h2>
      {graph === null ? <p className="note">…</p>
        : !graph.ok ? <p className="note">{graph.status === 404 ? t.noGraph : `${t.unreachable}: ${graph.reason}`}</p>
        : <><Graph nodes={graph.data.nodes} edges={graph.data.edges} onPick={pick} /><p className="note">{t.graphHint}</p></>}
      {entity && (
        <div className="report" aria-live="polite" style={{ marginTop: 8 }}>
          <b className="mono">{entity.id}</b>{"\n\n"}
          {entity.r === null ? "…" : entity.r.ok ? JSON.stringify(entity.r.data, null, 2) : entity.r.status === 404 ? t.noEntity : `${t.unreachable}: ${entity.r.reason}`}
        </div>
      )}

      <h2 style={{ marginTop: 16 }}>
        {t.evidence}
        <span className="aside">
          <button className="btn" disabled={evidence === "loading"} onClick={async () => { setEvidence("loading"); setEvidence(await api.incidentEvidence(inc.incident_id)); }}>{t.build}</button>
        </span>
      </h2>
      {evidence === null ? <p className="note">{t.notBuilt}</p>
        : evidence === "loading" ? <p className="note">…</p>
        : !evidence.ok ? <p className="note" role="alert">{evidence.status === 409 ? t.tamper : `${t.unreachable}: ${evidence.reason}`}</p>
        : (
          <>
            <p className="note"><b className="ok-text">{t.verified}</b> · {evidence.data.blocks.length} {t.blocks} · {fmtTime(evidence.data.built_at_ms, lang)} · <span className="mono">{evidence.data.package_id.slice(0, 40)}</span></p>
            <table className="data"><tbody>
              {evidence.data.blocks.map((b, i) => (
                <tr key={b.block_id + i} style={{ cursor: "default" }}><td className="num" style={{ width: 30 }}>{i}</td><td className="mono" style={{ fontSize: 12 }}>{b.block_id}</td></tr>
              ))}
            </tbody></table>
          </>
        )}

      <h2 style={{ marginTop: 16 }}>
        {t.incidentReport}
        <span className="aside">
          <select className="ctl" aria-label={t.incidentReport} value={rlang} onChange={(e) => { const v = e.target.value as "de" | "en"; setRlang(v); if (report) runReport(v); }}>
            <option value="de">DE</option><option value="en">EN</option>
          </select>
          <button className="btn" onClick={() => runReport()}>{t.report}</button>
        </span>
      </h2>
      {report === null ? <p className="note">{t.incidentReportHint}</p> : (
        <>
          <div className="report" aria-live="polite">{report}</div>
          {report !== "…" && <div className="actions"><button className="btn" onClick={() => downloadText(`fengarde-incident-${inc.incident_id}-${rlang}.md`, report)}>{t.download}</button></div>}
        </>
      )}

      <h2 style={{ marginTop: 16 }}>{t.members} ({inc.member_alert_ids.length})</h2>
      <div>{inc.member_alert_ids.map((id) => <a key={id} className="tag" href={`#/alarms/${encodeURIComponent(id)}`}>{id.length > 28 ? id.slice(0, 27) + "…" : id}</a>)}</div>
    </aside>
  );
}
