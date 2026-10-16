import { useEffect, useState, type FormEvent } from "react";
import { api, type ApiKeyMeta, type Asset, type Result } from "../data/api";
import { Panel } from "../hmi/hmi";
import { useConsole } from "../store";
import { S } from "./settings.i18n";

const fmtIso = (s: string | null | undefined, lang: string) => {
  if (!s) return "—";
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d.toLocaleString(lang);
};

export function Inventory({ selected, go }: { selected?: string; go: (hash: string) => void }) {
  const { t, lang, data, session, rbac } = useConsole();
  const s = S[lang];
  const isAdmin = rbac && session?.role === "admin";
  const [addMsg, setAddMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const reload = () => api.assets().then(setAssets);
  async function addDevice(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    const f = new FormData(form);
    const body: Record<string, string> = {};
    for (const k of ["mac", "hostname", "ip", "sector", "type"]) { const v = String(f.get(k) || "").trim(); if (v) body[k] = v; }
    const r = await api.addAsset(body as { mac: string });
    if (r.ok) { setAddMsg({ ok: true, text: `${r.data.new_device ? s.added : s.updated}: ${r.data.mac}` }); form.reset(); reload(); }
    else setAddMsg({ ok: false, text: r.reason });
  }
  const [assets, setAssets] = useState<Result<Asset[]> | null>(null);
  const [keys, setKeys] = useState<Result<{ keys: ApiKeyMeta[] }> | null>(null);
  const [q, setQ] = useState("");
  const [sector, setSector] = useState("");

  // Re-read with the console's poll so the list follows the pipeline (WS-6 enriches as events arrive).
  useEffect(() => { api.assets().then(setAssets); }, [data.fetchedAt]);
  useEffect(() => { api.keys().then(setKeys); }, []);

  const list = assets?.ok && Array.isArray(assets.data) ? assets.data : [];
  const sectors = [...new Set(list.map((a) => a.sector).filter(Boolean) as string[])].sort();
  const needle = q.trim().toLowerCase();
  const rows = list.filter((a) => (!sector || a.sector === sector)
    && (!needle || [a.mac, a.ip_current, a.hostname].some((v) => v?.toLowerCase().includes(needle))));
  const current = list.find((a) => a.mac === selected);

  return (
    <>
      <h1 className="view-title">{t.inventory}<small>{list.length} {t.assets.toLowerCase()}</small></h1>
      <div className="split">
        <div className="grid">
          <section className="panel">
            <div className="filters">
              <input className="ctl" type="search" aria-label={t.filterAsset} placeholder={t.filterAsset} value={q} onChange={(e) => setQ(e.target.value)} />
              <select className="ctl" aria-label={t.sector} value={sector} onChange={(e) => setSector(e.target.value)}>
                <option value="">{t.allSectors}</option>
                {sectors.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            {assets === null ? <p className="empty">…</p>
              : !assets.ok ? <p className="empty"><b>{t.unreachable}.</b> {assets.reason}</p>
              : rows.length === 0 ? <p className="empty">{list.length ? t.noData : t.noAssets}</p> : (
              <div className="table-wrap">
                <table className="data">
                  <thead><tr><th>{t.mac}</th><th>{t.hostname}</th><th>{t.ip}</th><th>{t.sector}</th><th>{t.type}</th><th>{t.status}</th></tr></thead>
                  <tbody>
                    {rows.map((a) => (
                      <tr key={a.mac} className="clk" aria-selected={a.mac === selected} onClick={() => go(`#/inventory/${encodeURIComponent(a.mac)}`)}>
                        <td className="mono">{a.mac}</td>
                        <td>{a.hostname || "—"}</td>
                        <td className="mono">{a.ip_current || "—"}</td>
                        <td>{a.sector || "—"}</td>
                        <td>{a.type || "—"}</td>
                        <td><span className={`pill ${a.status === "active" ? "ok" : "off"}`}>{a.status || "—"}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
          {isAdmin && (
            <Panel title={s.addDevice}>
              <p className="note">{s.addDeviceHint}</p>
              <form onSubmit={addDevice} className="filters" aria-label={s.addDevice}>
                <input className="ctl mono" name="mac" required placeholder="AA:BB:CC:DD:EE:FF" aria-label={s.mac} />
                <input className="ctl" name="hostname" placeholder={s.hostname} aria-label={s.hostname} />
                <input className="ctl mono" name="ip" placeholder={s.ip} aria-label={s.ip} />
                <select className="ctl" name="sector" aria-label={s.sector} defaultValue=""><option value="">{s.sector}</option><option value="bank">bank</option><option value="datacenter">datacenter</option><option value="common">common</option></select>
                <input className="ctl" name="type" placeholder={s.type} aria-label={s.type} />
                <button className="btn primary">{s.save}</button>
              </form>
              {addMsg && <p className={addMsg.ok ? "note" : "err"} role={addMsg.ok ? "status" : "alert"}>{addMsg.text}</p>}
            </Panel>
          )}
          <Panel title={t.apiKeys} aside={keys?.ok ? `${keys.data.keys.length}` : undefined}>
            {keys === null ? <p className="empty">…</p>
              : !keys.ok ? <p className="empty"><b>{t.unreachable}.</b> {keys.reason}</p>
              : keys.data.keys.length === 0 ? <p className="empty">{t.noKeys}</p> : (
              <div className="table-wrap">
                <table className="data">
                  <thead><tr><th>{t.keyId}</th><th>{t.tenant}</th><th>{t.scope}</th><th>{t.source}</th><th>{t.created}</th><th>{t.lastUsed}</th></tr></thead>
                  <tbody>
                    {keys.data.keys.map((k) => (
                      <tr key={k.key_id}>
                        <td className="mono">{k.key_id}</td><td>{k.tenant_id}</td><td>{k.scope || "—"}</td><td>{k.source || "—"}</td>
                        <td className="muted">{fmtIso(k.created_at, lang)}</td><td className="muted">{fmtIso(k.last_used_at, lang)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </div>
        {current ? <AssetFaceplate key={current.mac} snap={current} /> : <aside className="faceplate"><p className="empty">{t.select}</p></aside>}
      </div>
    </>
  );
}

/* Snapshot first (no blank flash), then the authoritative GET /assets/{mac}; a failed read keeps the snapshot. */
function AssetFaceplate({ snap }: { snap: Asset }) {
  const { t, lang } = useConsole();
  const [live, setLive] = useState<Asset | null | undefined>(undefined);
  useEffect(() => { api.asset(snap.mac).then((r) => setLive(r.ok ? r.data : null)); }, [snap.mac]);
  const a = live || snap;
  return (
    <aside className="faceplate" aria-label={t.inventory}>
      <h2>
        {a.type || "asset"} · {a.sector || "—"}
        <span className="aside">{live === undefined ? <span className="muted">{t.checking}</span> : live ? <span className="pill ok">{t.liveRecord}</span> : <span className="pill off">{t.snapshot}</span>}</span>
      </h2>
      <h3>{a.hostname || a.mac}</h3>
      <dl className="kv">
        <dt>{t.mac}</dt><dd className="mono">{a.mac}</dd>
        <dt>{t.ip}</dt><dd className="mono">{a.ip_current || "—"}</dd>
        <dt>{t.protocols}</dt><dd>{(a.protocols_seen || []).map((p) => <span key={p} className="tag">{p}</span>)}{!(a.protocols_seen || []).length && "—"}</dd>
        <dt>{t.lastSeen}</dt><dd>{fmtIso(a.last_seen, lang)}</dd>
        <dt>{t.tenant}</dt><dd>{a.tenant_id || "default"}</dd>
      </dl>
      <h2>{t.ipHistory}</h2>
      <table className="data">
        <thead><tr><th>IP</th><th>{t.firstSeen}</th><th>{t.lastSeen}</th></tr></thead>
        <tbody>
          {(a.ip_history || []).length === 0 ? <tr><td colSpan={3} className="muted">—</td></tr> : (a.ip_history || []).map((h, i) => (
            <tr key={h.ip + i}><td className="mono">{h.ip}</td><td className="muted">{fmtIso(h.from, lang)}</td><td className="muted">{h.to ? fmtIso(h.to, lang) : t.current}</td></tr>
          ))}
        </tbody>
      </table>
    </aside>
  );
}
