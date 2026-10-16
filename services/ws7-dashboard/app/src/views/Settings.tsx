import { useEffect, useState, type FormEvent } from "react";
import { api, type Result, type UserRow, type WebhookRow } from "../data/api";
import { Panel } from "../hmi/hmi";
import { useConsole } from "../store";
import { S } from "./settings.i18n";

const ROLES = ["read_only", "analyst", "admin"] as const;

/* Admin-only: user management and the (read-only) webhook list. Every action is a WS-3 session route,
   so a non-admin gets 404 from the backend as well; the guard here only avoids showing dead controls. */
export function Settings() {
  const { lang, session, rbac } = useConsole();
  const s = S[lang];
  const isAdmin = rbac && session?.role === "admin";
  const [users, setUsers] = useState<Result<{ users: UserRow[]; count: number }> | null>(null);
  const [hooks, setHooks] = useState<Result<{ webhooks: WebhookRow[]; count: number }> | null>(null);
  const [msg, setMsg] = useState("");
  const [editing, setEditing] = useState("");
  const [showDisabled, setShowDisabled] = useState(false);

  const load = () => { api.users().then(setUsers); api.webhooks().then(setHooks); };
  useEffect(() => { if (isAdmin) load(); }, [isAdmin]);

  if (!isAdmin) return (<><h1 className="view-title">{s.title}</h1><p className="empty">{s.adminOnly}</p></>);

  async function act(p: Promise<Result<unknown>>) {
    const r = await p;
    setMsg(r.ok ? "" : r.reason);
    if (r.ok) { setEditing(""); load(); }
  }

  async function create(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    const f = new FormData(form);
    const r = await api.createUser({
      username: String(f.get("username") || "").trim(), password: String(f.get("password") || ""),
      role: String(f.get("role") || "read_only"), tenant_id: String(f.get("tenant") || "").trim() || undefined,
    });
    setMsg(r.ok ? "" : r.reason);
    if (r.ok) { form.reset(); load(); }
  }

  const all = users?.ok ? users.data.users : [];
  const disabledCount = all.filter((u) => u.disabled).length;
  const list = showDisabled ? all : all.filter((u) => !u.disabled);
  return (
    <>
      <h1 className="view-title">{s.title}<small>{s.users} · {s.channels}</small></h1>
      <p className="err" role="alert">{msg}</p>
      <div className="grid">
        <Panel title={s.users} aside={users?.ok ? `${list.length}` : undefined}>
          <p className="note">{s.roleHint}</p>
          {disabledCount > 0 && (
            <label className="note" style={{ display: "inline-flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
              <input type="checkbox" style={{ width: "auto" }} checked={showDisabled} onChange={(e) => setShowDisabled(e.target.checked)} />
              {s.showDisabled} ({disabledCount})
            </label>
          )}
          {users === null ? <p className="empty">…</p> : !users.ok ? <p className="empty">{users.reason}</p> : (
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>{s.username}</th><th>{s.role}</th><th>{s.tenant}</th><th>{s.mfa}</th><th>{s.lastLogin}</th><th>{s.status}</th><th /></tr></thead>
                <tbody>
                  {list.map((u) => (
                    <tr key={u.username}>
                      <td className="mono">{u.username}{u.username === session?.username && <span className="pill ok" style={{ marginLeft: 8 }}>{s.you}</span>}</td>
                      <td>
                        <select className="ctl" aria-label={`${s.role} ${u.username}`} value={u.role}
                          onChange={(e) => act(api.updateUser(u.username, { role: e.target.value }))}>
                          {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                        </select>
                      </td>
                      <td>{u.tenant_id}</td>
                      <td><span className={`pill ${u.mfa_active ? "ok" : "off"}`}>{u.mfa_active ? s.active : "—"}</span></td>
                      <td className="muted">{u.last_login_at ? new Date(Number(u.last_login_at) * 1000).toLocaleString(lang) : s.never}</td>
                      <td><span className={`pill ${u.disabled ? "warn" : "ok"}`}>{u.disabled ? s.disabled : s.active}</span></td>
                      <td>
                        {editing === u.username ? (
                          <form onSubmit={(e) => { e.preventDefault(); act(api.updateUser(u.username, { password: String(new FormData(e.currentTarget).get("pw") || "") })); }}
                            style={{ display: "inline-flex", gap: 6 }}>
                            <input className="ctl" name="pw" type="password" autoComplete="new-password" minLength={12} required aria-label={s.newPw} placeholder={s.newPw} />
                            <button className="btn primary">{s.apply}</button>
                            <button type="button" className="btn" onClick={() => setEditing("")}>{s.cancel}</button>
                          </form>
                        ) : (
                          <>
                            <button className="btn" onClick={() => setEditing(u.username)}>{s.resetPw}</button>{" "}
                            <button className="btn" onClick={() => act(api.updateUser(u.username, { disabled: !u.disabled }))}>{u.disabled ? s.enable : s.disable}</button>
                          </>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <form onSubmit={create} className="filters" style={{ marginTop: 14 }} aria-label={s.newUser}>
            <input className="ctl" name="username" required autoComplete="off" aria-label={s.username} placeholder={s.username} />
            <input className="ctl" name="password" type="password" required minLength={12} autoComplete="new-password" aria-label={s.password} placeholder={s.password} />
            <select className="ctl" name="role" aria-label={s.role} defaultValue="read_only">{ROLES.map((r) => <option key={r} value={r}>{r}</option>)}</select>
            <input className="ctl" name="tenant" autoComplete="off" aria-label={s.tenant} placeholder={`${s.tenant} (${session?.tenant_id})`} />
            <button className="btn primary">{s.create}</button>
          </form>
        </Panel>

        <Panel title={s.channels} aside={hooks?.ok ? `${hooks.data.count}` : undefined}>
          <p className="note">{s.channelsHint}</p>
          {hooks === null ? <p className="empty">…</p> : !hooks.ok ? <p className="empty">{hooks.reason}</p>
            : hooks.data.webhooks.length === 0 ? <p className="empty">{s.noChannels}</p> : (
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>ID</th><th>{s.host}</th><th>{s.tenant}</th><th className="num">{s.minScore}</th><th>{s.secretEnv}</th><th>{s.status}</th></tr></thead>
                <tbody>
                  {hooks.data.webhooks.map((h) => (
                    <tr key={h.id}>
                      <td className="mono">{h.id}</td><td className="mono">{h.scheme}://{h.host}</td><td>{h.tenant_id || "—"}</td>
                      <td className="num">{h.min_score ?? "—"}</td><td className="mono">{h.secret_env}</td>
                      <td><span className={`pill ${h.enabled ? "ok" : "warn"}`}>{h.enabled ? s.canSend : s.noSecret}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}
