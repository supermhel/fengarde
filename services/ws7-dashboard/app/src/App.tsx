import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, setCsrf, type Session } from "./data/api";
import { AlarmShape, Icon, Shield } from "./hmi/hmi";
import { dicts, initialLang } from "./lib/i18n";
import { isAbnormal, rank } from "./lib/severity";
import { RANGES, ago, type RangeKey } from "./lib/time";
import { ConsoleProvider, triageOf, useConsole } from "./store";
import { Account } from "./views/Account";
import { Alarms } from "./views/Alarms";
import { Audit } from "./views/Audit";
import { Coverage } from "./views/Coverage";
import { Events } from "./views/Events";
import { Incidents } from "./views/Incidents";
import { Inventory } from "./views/Inventory";
import { Operations } from "./views/Operations";
import { Overview } from "./views/Overview";
import { Settings } from "./views/Settings";
import { Sources } from "./views/Sources";

type Auth = { state: "checking" } | { state: "login"; error?: string } | { state: "in"; session: Session | null; rbac: boolean };

export function App() {
  const [auth, setAuth] = useState<Auth>({ state: "checking" });

  useEffect(() => {
    api.me().then((r) => {
      if (r.ok) { setCsrf(r.data.csrf_token || null); setAuth({ state: "in", session: r.data, rbac: true }); }
      else if (r.status === 404) setAuth({ state: "in", session: null, rbac: false }); // RBAC off: no auth backend
      else if (r.status === 0) setAuth({ state: "in", session: null, rbac: false }); // unreachable: show the console, which says so
      else setAuth({ state: "login" });
    });
  }, []);

  const setSession = useCallback((s: Session | null) => {
    if (!s) { setCsrf(null); setAuth({ state: "login" }); }
  }, []);

  if (auth.state === "checking") return null;
  if (auth.state === "login") return <Login error={auth.error} onIn={(s) => { setCsrf(s.csrf_token || null); setAuth({ state: "in", session: s, rbac: true }); }} />;
  return (
    <ConsoleProvider session={auth.session} rbac={auth.rbac} setSession={setSession}>
      <Shell />
    </ConsoleProvider>
  );
}

function Login({ onIn, error }: { onIn: (s: Session) => void; error?: string }) {
  const t = dicts[initialLang()];
  const [err, setErr] = useState(error || "");
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true); setErr("");
    const r = await api.login(String(f.get("username") || ""), String(f.get("password") || ""));
    setBusy(false);
    if (r.ok) onIn(r.data);
    else setErr(r.status === 429 ? t.tooMany : r.status === 0 ? `${t.unreachable}.` : r.reason || t.signInFailed);
  }
  return (
    <div className="login">
      <form onSubmit={submit} aria-label={t.signIn}>
        <Shield size={34} />
        <h1>FENGARDE</h1>
        <p className="muted" style={{ margin: 0 }}>{t.signIn}</p>
        <label htmlFor="u">{t.username}</label>
        <input id="u" name="username" autoComplete="username" required autoFocus />
        <label htmlFor="p">{t.password}</label>
        <input id="p" name="password" type="password" autoComplete="current-password" required />
        <p className="err" role="alert">{err}</p>
        <button className="btn primary" disabled={busy}>{busy ? "…" : t.signIn}</button>
      </form>
    </div>
  );
}

function useHash(): [string, (h: string) => void] {
  const [h, setH] = useState(location.hash || "#/overview");
  useEffect(() => {
    const on = () => setH(location.hash || "#/overview");
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return [h, useCallback((n: string) => { if (location.hash !== n) location.hash = n; }, [])];
}

function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState<string>(() => { try { return localStorage.getItem("fg.theme") || "light"; } catch { return "light"; } });
  useEffect(() => { document.documentElement.dataset.theme = theme; try { localStorage.setItem("fg.theme", theme); } catch { /* blocked */ } }, [theme]);
  return [theme, () => setTheme((x) => (x === "light" ? "dark" : "light"))];
}

function Shell() {
  const { t, lang, setLang, range, setRange, data, session, rbac, setSession, triage, tenant, setTenantScope, tenants } = useConsole();
  const [hash, go] = useHash();
  const [theme, toggleTheme] = useTheme();
  const [, view, arg] = hash.split("/");
  const sel = arg ? decodeURIComponent(arg) : undefined;

  const alerts = data.alerts?.ok ? data.alerts.data : [];
  const active = alerts.filter((a) => isAbnormal(a.level, triageOf(a, triage).status)).sort((a, b) => rank(b.level) - rank(a.level) || b.time - a.time);
  const unack = active.filter((a) => triageOf(a, triage).status === "new").length;
  const incidents = data.incidents?.ok ? data.incidents.data.count : 0;
  const live = data.alerts?.ok === true;
  const isAdmin = rbac && session?.role === "admin";

  type Item = [key: string, label: string, count?: number, alarm?: boolean];
  const operate: Item[] = [["sources", t.sources], ["inventory", t.inventory], ["operations", t.operations], ["audit", t.audit]];
  if (isAdmin) operate.push(["settings", t.settings]);
  const groups: [string, Item[]][] = [
    [t.detect, [["overview", t.overview], ["alarms", t.alarms, active.length, true], ["incidents", t.incidents, incidents]]],
    [t.investigate, [["events", t.events], ["coverage", t.coverage]]],
    [t.operate, operate],
  ];

  return (
    <div className="shell">
      <span className="brand"><Shield /> FENGARDE</span>
      <header className="top">
        <span className={`chip ${data.alerts === null ? "" : live ? "ok" : "down"}`}><span className="dot" />{data.alerts === null ? "…" : live ? `${t.live} · ${ago(data.fetchedAt, lang)}` : t.unavailable}</span>
        <span className="spacer" />
        {isAdmin && tenants.length > 1 && (
          <select className="ctl" aria-label={t.tenant} value={tenant} onChange={(e) => setTenantScope(e.target.value)}>
            <option value="">{t.allTenants}</option>
            {tenants.map((x) => <option key={x} value={x}>{x}</option>)}
          </select>
        )}
        <select className="ctl" aria-label={t.time} value={range} onChange={(e) => setRange(e.target.value as RangeKey)}>
          {(Object.keys(RANGES) as RangeKey[]).map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
        <span className="seg" role="group" aria-label="Language">
          <button aria-pressed={lang === "de"} onClick={() => setLang("de")}>DE</button>
          <button aria-pressed={lang === "en"} onClick={() => setLang("en")}>EN</button>
        </span>
        <button className="ctl icon-btn" onClick={toggleTheme} aria-label="Toggle dark theme" aria-pressed={theme === "dark"}><Icon name={theme === "dark" ? "moon" : "sun"} size={16} /></button>
        {rbac && session && (
          <>
            <a className="chip user" href="#/account"><span className="av">{session.username.slice(0, 2)}</span>{session.username} · {session.role}</a>
            <button className="ctl" onClick={async () => { await api.logout(); setSession(null); }}>{t.signOut}</button>
          </>
        )}
      </header>

      <div className={`banner ${active.length ? "active" : "quiet"}`} role="status" aria-live="polite">
        <span className="label">{active.length ? <><span className="n">{active.length}</span>{t.alarmsActive} · {unack} {t.unack}</> : t.noAlarms}</span>
        <span className="items">
          {active.length === 0 ? (
            <span className="muted">{live ? `${alerts.length} ${t.alarms.toLowerCase()} · ${t.checked} ${ago(data.fetchedAt, lang)}` : t.unavailable}</span>
          ) : active.slice(0, 4).map((a) => (
            <button key={a.alert_id} className={`item${triageOf(a, triage).status === "new" ? " unack" : ""}`} onClick={() => go(`#/alarms/${encodeURIComponent(a.alert_id)}`)}>
              <AlarmShape level={a.level} />{a.rule_title}<span className="muted mono">{a.src_endpoint?.ip}</span>
            </button>
          ))}
        </span>
        {active.length > 0 && <button className="btn" onClick={() => go(`#/alarms/${encodeURIComponent(active[0].alert_id)}`)}>{t.openTop}</button>}
      </div>

      <nav className="nav" aria-label="Views">
        {groups.map(([g, items]) => (
          <div key={g} style={{ display: "contents" }}>
            <span className="group">{g}</span>
            {items.map(([k, label, n, alarm]) => (
              <a key={k} href={`#/${k}`} aria-current={view === k ? "page" : undefined}>
                <Icon name={k} />{label}{n ? <span className={`count${alarm ? " alarm" : ""}`}>{n}</span> : null}
              </a>
            ))}
          </div>
        ))}
        <a className="classic" href="legacy/"><Icon name="classic" size={16} />{t.classic}</a>
      </nav>

      <main>
        {view === "alarms" ? <Alarms selected={sel} go={go} />
          : view === "incidents" ? <Incidents selected={sel} go={go} />
          : view === "events" ? <Events />
          : view === "coverage" ? <Coverage />
          : view === "sources" ? <Sources />
          : view === "inventory" ? <Inventory selected={sel} go={go} />
          : view === "operations" ? <Operations />
          : view === "audit" ? <Audit />
          : view === "settings" ? <Settings />
          : view === "account" ? <Account />
          : <Overview go={go} />}
      </main>
    </div>
  );
}
