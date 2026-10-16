import { useEffect, useState } from "react";
import { api, type AuditEntry, type Result } from "../data/api";
import { useConsole } from "../store";

/* Admin audit trail (GET /audit, append-only, admin-scoped by the backend). */
export function Audit() {
  const { t, lang, data } = useConsole();
  const [res, setRes] = useState<Result<{ entries: AuditEntry[]; count: number }> | null>(null);
  useEffect(() => { api.audit().then(setRes); }, [data.fetchedAt]);
  const rows = res?.ok ? res.data.entries : [];

  return (
    <>
      <h1 className="view-title">{t.auditTrail}<small>{rows.length}</small></h1>
      <section className="panel">
        <p className="hint">{t.auditHint}</p>
        {res === null ? <p className="empty">…</p>
          : !res.ok ? <p className="empty"><b>{res.status === 401 || res.status === 403 ? t.noAudit : `${t.unreachable}.`}</b> {res.status === 401 || res.status === 403 ? "" : res.reason}</p>
          : rows.length === 0 ? <p className="empty">{t.noAudit}</p> : (
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>{t.time}</th><th>{t.event}</th><th>{t.actor}</th><th>{t.tenant}</th><th>{t.detail}</th></tr></thead>
              <tbody>
                {rows.map((e, i) => (
                  <tr key={e.ts + i}>
                    <td className="muted" style={{ whiteSpace: "nowrap" }}>{new Date(e.ts).toLocaleString(lang)}</td>
                    <td><span className={`pill${/fail|denied|lock/.test(e.event) ? "" : " ok"}`}>{e.event}</span></td>
                    <td>{e.actor}</td>
                    <td className="muted">{e.tenant_id || "—"}</td>
                    <td className="mono" style={{ fontSize: 12, overflowWrap: "anywhere" }}>{e.detail ? JSON.stringify(e.detail) : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
